/*
 * Copyright 2023 The Backstage Authors
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

import {
  AppTranslationApi,
  TranslationMessages,
  TranslationRef,
  TranslationResource,
} from '@backstage/core-plugin-api/alpha';
import i18next, { type i18n } from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

// Internal import to avoid code duplication, this will lead to duplication in build output
// eslint-disable-next-line @backstage/no-relative-monorepo-imports
import { toInternalTranslationResource } from '../../../../../core-plugin-api/src/translation/TranslationResource';
// eslint-disable-next-line @backstage/no-relative-monorepo-imports
import { toInternalTranslationRef } from '../../../../../core-plugin-api/src/translation/TranslationRef';

const DEFAULT_LANGUAGE = 'en';

/** @alpha */
export type ExperimentalI18n = {
  fallbackLanguage?: string | string[];
  supportedLanguages?: string[];
  resources?: Array<TranslationMessages | TranslationResource>;
};

function removeNulls(
  messages: Record<string, string | null>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(messages).filter(
      (e): e is [string, string] => e[1] !== null,
    ),
  );
}

/** @alpha */
export class AppTranslationApiImpl implements AppTranslationApi {
  static create(options?: ExperimentalI18n) {
    const i18n = i18next.createInstance().use(initReactI18next);

    i18n.use(LanguageDetector);

    i18n.init({
      fallbackLng: options?.fallbackLanguage || DEFAULT_LANGUAGE,
      supportedLngs: options?.supportedLanguages || [DEFAULT_LANGUAGE],
      interpolation: {
        escapeValue: false,
      },
      react: {
        bindI18n: 'loaded languageChanged',
      },
    });

    return new AppTranslationApiImpl(i18n, options);
  }

  private readonly cache = new Set<string>();
  private readonly lazyCache = new Map<string, Set<string>>();

  getI18n() {
    return this.i18n;
  }

  initMessages(options?: ExperimentalI18n) {
    for (const resource of options?.resources || []) {
      if (resource.$$type === '@backstage/TranslationResource') {
        this.addLazyResources(resource);
      } else if (resource.$$type === '@backstage/TranslationMessages') {
        // Overrides for default messages, created with createTranslationMessages and installed via app
        this.addMessages(resource);
      }
    }
  }

  addResource(translationRef: TranslationRef): void {
    const internalRef = toInternalTranslationRef(translationRef);
    const defaultResource = internalRef.getDefaultResource();
    if (defaultResource) {
      this.addLazyResources(defaultResource);
    }
  }

  addMessages(messages: TranslationMessages) {
    if (this.cache.has(messages.id)) {
      return;
    }
    this.cache.add(messages.id);
    this.i18n.addResourceBundle(
      DEFAULT_LANGUAGE,
      messages.id,
      removeNulls(messages.messages),
      true,
      false,
    );
  }

  addLazyResources(resource: TranslationResource) {
    let cache = this.lazyCache.get(resource.id);

    if (!cache) {
      cache = new Set();
      this.lazyCache.set(resource.id, cache);
    }

    const {
      language: currentLanguage,
      services,
      options,
      addResourceBundle,
      reloadResources,
    } = this.i18n;

    if (cache.has(currentLanguage)) {
      return;
    }

    const internalResource = toInternalTranslationResource(resource);
    const namespace = internalResource.id;

    Promise.allSettled((options.supportedLngs || []).map(addLanguage)).then(
      results => {
        if (results.some(result => result.status === 'fulfilled')) {
          this.i18n.emit('loaded');
        }
      },
    );

    async function addLanguage(language: string) {
      if (cache!.has(language)) {
        return;
      }

      cache!.add(language);

      let loadBackend: Promise<void> | undefined;

      if (services.backendConnector?.backend) {
        loadBackend = reloadResources([language], [namespace]);
      }

      const loadLazyResources = internalResource.resources.find(
        entry => entry.language === language,
      )?.loader;

      if (!loadLazyResources) {
        await loadBackend;
        return;
      }

      const [result] = await Promise.allSettled([
        loadLazyResources(),
        loadBackend,
      ]);

      if (result.status === 'rejected') {
        throw result.reason;
      }

      addResourceBundle(
        language,
        namespace,
        result.value.messages,
        true,
        false,
      );
    }
  }

  private constructor(private readonly i18n: i18n, options?: ExperimentalI18n) {
    this.initMessages(options);
  }
}
