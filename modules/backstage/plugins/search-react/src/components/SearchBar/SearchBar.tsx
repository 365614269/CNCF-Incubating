/*
 * Copyright 2022 The Backstage Authors
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
  AnalyticsContext,
  configApiRef,
  useApi,
} from '@backstage/core-plugin-api';
import { IconButton, InputAdornment, TextField } from '@material-ui/core';
import Button from '@material-ui/core/Button';
import { TextFieldProps } from '@material-ui/core/TextField';
import SearchIcon from '@material-ui/icons/Search';
import React, {
  ChangeEvent,
  ComponentType,
  forwardRef,
  ForwardRefExoticComponent,
  KeyboardEvent,
  useCallback,
  useEffect,
  useState,
} from 'react';
import useDebounce from 'react-use/lib/useDebounce';

import { SearchContextProvider, useSearch } from '../../context';
import { TrackSearch } from '../SearchTracker';

function withContext<T>(Component: ComponentType<T>) {
  return forwardRef<HTMLDivElement, T>((props, ref) => (
    <SearchContextProvider inheritParentContextIfAvailable>
      <Component {...props} ref={ref} />
    </SearchContextProvider>
  ));
}

/**
 * Props for {@link SearchBarBase}.
 *
 * @public
 */
export type SearchBarBaseProps = Omit<TextFieldProps, 'onChange'> & {
  debounceTime?: number;
  clearButton?: boolean;
  onClear?: () => void;
  onSubmit?: () => void;
  onChange: (value: string) => void;
  endAdornment?: React.ReactNode;
};

/**
 * All search boxes exported by the search plugin are based on the <SearchBarBase />,
 * and this one is based on the <InputBase /> component from Material UI.
 * Recommended if you don't use Search Provider or Search Context.
 *
 * @public
 */
export const SearchBarBase: ForwardRefExoticComponent<SearchBarBaseProps> =
  withContext(
    forwardRef((props, ref) => {
      const {
        onChange,
        onKeyDown = () => {},
        onClear = () => {},
        onSubmit = () => {},
        debounceTime = 200,
        clearButton = true,
        fullWidth = true,
        value: defaultValue,
        label,
        placeholder,
        inputProps = {},
        InputProps = {},
        endAdornment,
        ...rest
      } = props;

      const configApi = useApi(configApiRef);
      const [value, setValue] = useState<string>('');

      useEffect(() => {
        setValue(prevValue =>
          prevValue !== defaultValue ? String(defaultValue) : prevValue,
        );
      }, [defaultValue]);

      useDebounce(() => onChange(value), debounceTime, [value]);

      const handleChange = useCallback(
        (e: ChangeEvent<HTMLInputElement>) => {
          setValue(e.target.value);
        },
        [setValue],
      );

      const handleKeyDown = useCallback(
        (e: KeyboardEvent<HTMLDivElement>) => {
          if (onKeyDown) onKeyDown(e);
          if (onSubmit && e.key === 'Enter') {
            onSubmit();
          }
        },
        [onKeyDown, onSubmit],
      );

      const handleClear = useCallback(() => {
        onChange('');
        if (onClear) {
          onClear();
        }
      }, [onChange, onClear]);

      const ariaLabel: string | undefined = label ? undefined : 'Search';

      const inputPlaceholder =
        placeholder ??
        `Search in ${configApi.getOptionalString('app.title') || 'Backstage'}`;

      const startAdornment = (
        <InputAdornment position="start">
          <IconButton aria-label="Query" size="small" disabled>
            <SearchIcon />
          </IconButton>
        </InputAdornment>
      );

      const clearButtonEndAdornment = (
        <InputAdornment position="end">
          <Button
            aria-label="Clear"
            size="small"
            onClick={handleClear}
            onKeyDown={event => {
              if (event.key === 'Enter') {
                // write your functionality here
                event.stopPropagation();
              }
            }}
          >
            Clear
          </Button>
        </InputAdornment>
      );

      return (
        <TrackSearch>
          <TextField
            id="search-bar-text-field"
            data-testid="search-bar-next"
            variant="outlined"
            margin="normal"
            inputRef={ref}
            value={value}
            label={label}
            placeholder={inputPlaceholder}
            InputProps={{
              startAdornment,
              endAdornment: clearButton
                ? clearButtonEndAdornment
                : endAdornment,
              ...InputProps,
            }}
            inputProps={{
              'aria-label': ariaLabel,
              ...inputProps,
            }}
            fullWidth={fullWidth}
            onChange={handleChange}
            onKeyDown={handleKeyDown}
            {...rest}
          />
        </TrackSearch>
      );
    }),
  );

/**
 * Props for {@link SearchBar}.
 *
 * @public
 */
export type SearchBarProps = Partial<SearchBarBaseProps>;

/**
 * Recommended search bar when you use the Search Provider or Search Context.
 *
 * @public
 */
export const SearchBar: ForwardRefExoticComponent<SearchBarProps> = withContext(
  forwardRef((props, ref) => {
    const { value: initialValue = '', onChange, ...rest } = props;

    const { term, setTerm } = useSearch();

    useEffect(() => {
      if (initialValue) {
        setTerm(String(initialValue));
      }
    }, [initialValue, setTerm]);

    const handleChange = useCallback(
      (newValue: string) => {
        if (onChange) {
          onChange(newValue);
        } else {
          setTerm(newValue);
        }
      },
      [onChange, setTerm],
    );

    return (
      <AnalyticsContext
        attributes={{ pluginId: 'search', extension: 'SearchBar' }}
      >
        <SearchBarBase
          {...rest}
          ref={ref}
          value={term}
          onChange={handleChange}
        />
      </AnalyticsContext>
    );
  }),
);
