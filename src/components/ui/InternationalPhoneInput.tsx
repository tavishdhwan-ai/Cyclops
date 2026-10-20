'use client';

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { ChevronDown, Search, Check } from 'lucide-react';
import {
  COUNTRIES,
  CountryInfo,
  getDefaultCountry,
  normalizePhoneNumber,
} from '../../lib/phoneUtils';

interface InternationalPhoneInputProps {
  value: string;
  onChange: (e164Value: string, isValid: boolean, error?: string) => void;
  disabled?: boolean;
  error?: string | null;
  id?: string;
  autoFocus?: boolean;
}

export const InternationalPhoneInput: React.FC<InternationalPhoneInputProps> = ({
  value,
  onChange,
  disabled = false,
  error = null,
  id = 'international-phone-input',
  autoFocus = false,
}) => {
  const [selectedCountry, setSelectedCountry] = useState<CountryInfo>(() => getDefaultCountry());
  const [nationalNumber, setNationalNumber] = useState('');
  const [prevValue, setPrevValue] = useState(value);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const dropdownRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Synchronize incoming value if externally changed (React recommended pattern)
  if (value !== prevValue) {
    setPrevValue(value);
    if (value && value.startsWith('+')) {
      const parsed = normalizePhoneNumber(value);
      if (parsed.countryCode) {
        const country = COUNTRIES.find((c) => c.iso2 === parsed.countryCode);
        if (country) {
          setSelectedCountry(country);
          if (parsed.formattedNational) {
            setNationalNumber(parsed.formattedNational);
          }
        }
      }
    } else if (!value) {
      setNationalNumber('');
    }
  }

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsDropdownOpen(false);
      }
    }
    if (isDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      // Auto focus search input when opened
      setTimeout(() => searchInputRef.current?.focus(), 50);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isDropdownOpen]);

  // Filter countries by name, code, or dialCode
  const filteredCountries = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return COUNTRIES;
    return COUNTRIES.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.dialCode.includes(q) ||
        c.iso2.toLowerCase().includes(q)
    );
  }, [searchQuery]);

  // Handle phone input changes
  const handleNumberChange = (rawInput: string) => {
    setNationalNumber(rawInput);
    // Combine selected country dial code with user input if no leading + provided
    const combined = rawInput.startsWith('+')
      ? rawInput
      : `${selectedCountry.dialCode} ${rawInput}`;

    const validation = normalizePhoneNumber(combined, selectedCountry.iso2);
    onChange(validation.normalized, validation.isValid, validation.error);
  };

  // Handle country selection
  const handleCountrySelect = (country: CountryInfo) => {
    setSelectedCountry(country);
    setIsDropdownOpen(false);
    setSearchQuery('');

    // Revalidate with new dial code
    if (nationalNumber) {
      const combined = `${country.dialCode} ${nationalNumber}`;
      const validation = normalizePhoneNumber(combined, country.iso2);
      onChange(validation.normalized, validation.isValid, validation.error);
    }
  };

  return (
    <div className="space-y-1.5" ref={dropdownRef}>
      <div className="relative flex items-center rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 focus-within:ring-2 focus-within:ring-zinc-400 dark:focus-within:ring-zinc-600 transition-colors">
        {/* Country Selector Trigger */}
        <button
          type="button"
          disabled={disabled}
          onClick={() => setIsDropdownOpen(!isDropdownOpen)}
          aria-label={`Select country code. Current country: ${selectedCountry.name} (${selectedCountry.dialCode})`}
          className="flex items-center gap-1.5 px-3 py-2.5 text-xs font-semibold text-zinc-800 dark:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-900 border-r border-zinc-200 dark:border-zinc-800 rounded-l-lg transition-colors shrink-0 cursor-pointer disabled:opacity-50"
        >
          <span className="text-base leading-none" role="img" aria-label={selectedCountry.name}>
            {selectedCountry.flag}
          </span>
          <span className="font-mono text-xs">{selectedCountry.dialCode}</span>
          <ChevronDown className="h-3 w-3 text-zinc-400" />
        </button>

        {/* National Number Input */}
        <div className="relative flex-1">
          <input
            id={id}
            type="tel"
            autoComplete="tel"
            disabled={disabled}
            autoFocus={autoFocus}
            value={nationalNumber}
            onChange={(e) => handleNumberChange(e.target.value)}
            placeholder="Mobile number"
            className="w-full bg-transparent px-3 py-2.5 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-hidden"
          />
        </div>
      </div>

      {/* Country Dropdown Menu */}
      {isDropdownOpen && (
        <div className="absolute z-50 mt-1 w-72 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-100">
          {/* Search Header */}
          <div className="p-2 border-b border-zinc-100 dark:border-zinc-800 flex items-center gap-2">
            <Search className="h-3.5 w-3.5 text-zinc-400 shrink-0 ml-1" />
            <input
              ref={searchInputRef}
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search country or code..."
              className="w-full bg-transparent text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 focus:outline-hidden py-1"
            />
          </div>

          {/* Country List */}
          <div className="max-h-60 overflow-y-auto p-1 space-y-0.5">
            {filteredCountries.length > 0 ? (
              filteredCountries.map((country) => {
                const isSelected = country.iso2 === selectedCountry.iso2;
                return (
                  <button
                    key={country.iso2}
                    type="button"
                    onClick={() => handleCountrySelect(country)}
                    className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-zinc-100 dark:bg-zinc-800 font-semibold text-zinc-900 dark:text-white'
                        : 'text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-sm leading-none shrink-0">{country.flag}</span>
                      <span className="truncate">{country.name}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0 font-mono text-[11px] text-zinc-400">
                      <span>{country.dialCode}</span>
                      {isSelected && <Check className="h-3.5 w-3.5 text-zinc-900 dark:text-white" />}
                    </div>
                  </button>
                );
              })
            ) : (
              <div className="p-3 text-center text-xs text-zinc-400">
                No matching country found.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <p className="text-[11px] font-medium text-red-600 dark:text-red-400" role="alert">
          {error}
        </p>
      )}
    </div>
  );
};
