/*
 * Copyright 2024 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { WebSocket } from 'ws';
import { EventSubscriber } from '@backstage/plugin-events-node';
import { SignalManager } from './SignalManager';
import { getVoidLogger } from '@backstage/backend-common';

class MockWebSocket {
  closed: boolean = false;
  readyState: number = WebSocket.OPEN;
  callbacks: Map<string | symbol, (this: WebSocket, ...args: any[]) => void> =
    new Map();
  data: any[] = [];

  close(_: number, __: string | Buffer): void {
    this.readyState = WebSocket.CLOSED;
    this.closed = true;
  }

  on(
    event: string | symbol,
    listener: (this: WebSocket, ...args: any[]) => void,
  ) {
    this.callbacks.set(event, listener);
    return this;
  }

  // @ts-ignore
  send(data: any, _?: (err?: Error) => void): void {
    this.data.push(data);
  }

  trigger(event: string | symbol, ...args: any[]): void {
    const cb = this.callbacks.get(event);
    if (!cb) {
      throw new Error(`No callback for ${event.toString()}`);
    }
    // @ts-ignore
    cb(...args);
  }
}

describe('SignalManager', () => {
  let onEvent: Function;

  const mockEventBroker = {
    publish: async () => {},
    subscribe: (subscriber: EventSubscriber) => {
      onEvent = subscriber.onEvent;
    },
  };

  const manager = SignalManager.create({
    eventBroker: mockEventBroker,
    logger: getVoidLogger(),
  });

  it('should close connection on error', () => {
    const ws = new MockWebSocket();
    manager.addConnection(ws as unknown as WebSocket);

    ws.trigger('error', new Error('error'));
    expect(ws.closed).toBeTruthy();
  });

  it('should allow subscribing and unsubscribing to events', async () => {
    const ws = new MockWebSocket();
    manager.addConnection(ws as unknown as WebSocket);

    ws.trigger(
      'message',
      JSON.stringify({ action: 'subscribe', channel: 'test' }),
      false,
    );

    await onEvent({
      topic: 'signals',
      eventPayload: {
        recipients: null,
        channel: 'test',
        message: { msg: 'test' },
      },
    });

    expect(ws.data.length).toEqual(1);
    expect(ws.data[0]).toEqual(
      JSON.stringify({ channel: 'test', message: { msg: 'test' } }),
    );

    ws.trigger(
      'message',
      JSON.stringify({ action: 'unsubscribe', channel: 'test' }),
      false,
    );

    await onEvent({
      topic: 'signals',
      eventPayload: {
        recipients: null,
        channel: 'test',
        message: { msg: 'test' },
      },
    });

    expect(ws.data.length).toEqual(1);
  });

  it('should only send to users from identity', async () => {
    // Connection without identity
    const ws1 = new MockWebSocket();
    manager.addConnection(ws1 as unknown as WebSocket);

    // Connection with identity and subscription
    const ws2 = new MockWebSocket();
    manager.addConnection(ws2 as unknown as WebSocket, {
      identity: {
        type: 'user',
        ownershipEntityRefs: ['user:default/john.doe'],
        userEntityRef: 'user:default/john.doe',
      },
      expiresInSeconds: 3600,
      token: '1234',
    });

    // Connection without subscription
    const ws3 = new MockWebSocket();
    manager.addConnection(ws3 as unknown as WebSocket, {
      identity: {
        type: 'user',
        ownershipEntityRefs: ['user:default/john.doe'],
        userEntityRef: 'user:default/john.doe',
      },
      expiresInSeconds: 3600,
      token: '1234',
    });

    ws1.trigger(
      'message',
      JSON.stringify({ action: 'subscribe', channel: 'test' }),
      false,
    );

    ws2.trigger(
      'message',
      JSON.stringify({ action: 'subscribe', channel: 'test' }),
      false,
    );

    await onEvent({
      topic: 'signals',
      eventPayload: {
        recipients: 'user:default/john.doe',
        channel: 'test',
        message: { msg: 'test' },
      },
    });

    expect(ws1.data.length).toEqual(0);
    expect(ws3.data.length).toEqual(0);
    expect(ws2.data.length).toEqual(1);
    expect(ws2.data[0]).toEqual(
      JSON.stringify({ channel: 'test', message: { msg: 'test' } }),
    );
  });
});
