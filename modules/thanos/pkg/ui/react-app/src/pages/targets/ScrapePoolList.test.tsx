import * as React from 'react';
import { mount, ReactWrapper } from 'enzyme';
import { act } from 'react-dom/test-utils';
import { UncontrolledAlert } from 'reactstrap';
import { sampleApiResponse } from './__testdata__/testdata';
import ScrapePoolList, { ScrapePoolPanel } from './ScrapePoolList';
import { Target } from './target';
import { FetchMock } from 'jest-fetch-mock/types';

describe('ScrapePoolList', () => {
  const defaultProps = {
    pathPrefix: '..',
  };

  beforeEach(() => {
    fetchMock.resetMocks();
  });

  describe('when data is returned', () => {
    let scrapePoolList: ReactWrapper;
    let mock: FetchMock;
    beforeEach(() => {
      //Tooltip requires DOM elements to exist. They do not in enzyme rendering so we must manually create them.
      const scrapePools: { [key: string]: number } = { blackbox: 3, node_exporter: 1, 'prometheus/test': 1 };
      Object.keys(scrapePools).forEach((pool: string): void => {
        Array.from(Array(scrapePools[pool]).keys()).forEach((idx: number): void => {
          const div = document.createElement('div');
          div.id = `series-labels-${pool}-${idx}`;
          document.body.appendChild(div);
        });
      });
      mock = fetchMock.mockResponse(JSON.stringify(sampleApiResponse));
    });

    it('renders a table', async () => {
      await act(async () => {
        scrapePoolList = mount(<ScrapePoolList {...defaultProps} />);
      });
      scrapePoolList.update();
      expect(mock).toHaveBeenCalledWith('../api/v1/targets?state=active', { cache: 'no-store', credentials: 'same-origin' });
      const panels = scrapePoolList.find(ScrapePoolPanel);
      expect(panels).toHaveLength(3);
      const activeTargets: Target[] = sampleApiResponse.data.activeTargets as unknown as Target[];
      activeTargets.forEach(({ scrapePool }: Target) => {
        const panel = scrapePoolList.find(ScrapePoolPanel).filterWhere((panel) => panel.prop('scrapePool') === scrapePool);
        expect(panel).toHaveLength(1);
      });
    });
  });

  describe('when an error is returned', () => {
    it('displays an alert', async () => {
      const mock = fetchMock.mockReject(new Error('Error fetching targets'));

      let scrapePoolList: any;
      await act(async () => {
        scrapePoolList = mount(<ScrapePoolList {...defaultProps} />);
      });
      scrapePoolList.update();

      expect(mock).toHaveBeenCalledWith('../api/v1/targets?state=active', { cache: 'no-store', credentials: 'same-origin' });
      const alert = scrapePoolList.find(UncontrolledAlert);
      expect(alert.prop('color')).toBe('danger');
      expect(alert.text()).toContain('Error fetching targets');
    });
  });
});
