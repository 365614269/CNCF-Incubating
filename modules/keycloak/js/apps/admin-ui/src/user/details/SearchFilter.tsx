import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Dropdown,
  DropdownItem,
  DropdownToggle,
  Select,
  SelectOption,
  ToolbarItem,
} from "@patternfly/react-core";
import { FilterIcon } from "@patternfly/react-icons";

export type SearchType = "default" | "attribute";

type SearchToolbarProps = SearchDropdownProps;

type SearchDropdownProps = {
  searchType: SearchType;
  onSelect: (value: SearchType) => void;
};

export const SearchDropdown = ({
  searchType,
  onSelect,
}: SearchDropdownProps) => {
  const { t } = useTranslation("users");
  const [searchToggle, setSearchToggle] = useState(false);

  const createDropdown = (searchType: SearchType) => (
    <DropdownItem
      key={searchType}
      onClick={() => {
        onSelect(searchType);
        setSearchToggle(false);
      }}
    >
      {t(`searchType.${searchType}`)}
    </DropdownItem>
  );
  const options = [createDropdown("default"), createDropdown("attribute")];

  return (
    <Dropdown
      className="keycloak__users__searchtype"
      toggle={
        <DropdownToggle id="toggle-id" onToggle={setSearchToggle}>
          <FilterIcon /> {t(`searchType.${searchType}`)}
        </DropdownToggle>
      }
      isOpen={searchToggle}
      dropdownItems={options}
    />
  );
};

export const SearchToolbar = ({ searchType, onSelect }: SearchToolbarProps) => {
  const { t } = useTranslation("users");
  const [open, setOpen] = useState(false);

  return (
    <>
      <ToolbarItem>
        <SearchDropdown searchType={searchType} onSelect={onSelect} />
      </ToolbarItem>
      <ToolbarItem>
        <Select
          className="keycloak__users__searchtype"
          onToggle={setOpen}
          isOpen={open}
          selections={[t("default"), t("attribute")]}
          onSelect={() => setOpen(false)}
        >
          <SelectOption value={"default"}>{t("default")}</SelectOption>
          <SelectOption value={"attribute"}>{t("attribute")}</SelectOption>
        </Select>
      </ToolbarItem>
    </>
  );
};
