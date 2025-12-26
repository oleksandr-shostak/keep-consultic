import clsx from "clsx";
import Select, { ClassNamesConfig } from "react-select";
import { useIncidentActions } from "@/entities/incidents/model";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useUsers } from "@/entities/users/model/useUsers";
import { UserCircleIcon } from "@heroicons/react/24/outline";

const customClassNames: ClassNamesConfig<any, false, any> = {
  container: () => "inline-flex",
  control: (state) =>
    clsx(
      "p-1 min-w-14 !rounded-full !min-h-0",
      state.isFocused ? "border-orange-500" : ""
    ),
  valueContainer: () => "!p-0",
  dropdownIndicator: () => "!p-0",
  indicatorSeparator: () => "hidden",
  menuList: () => "!p-0",
  menu: () => "!p-0 !overflow-hidden min-w-48",
  option: (state) =>
    clsx(
      "!p-1",
      state.isSelected ? "!bg-orange-500 !text-white" : "",
      state.isFocused && !state.isSelected ? "!bg-slate-100" : ""
    ),
};

type Props = {
  incidentId: string;
  value: string | null;
  onChange?: (assignee: string | null) => void;
  className?: string;
};

export function IncidentChangeAssigneeSelect({
  incidentId,
  value,
  onChange,
  className,
}: Props) {
  const menuPortalTarget = useRef<HTMLElement | null>(null);
  const [isDisabled, setIsDisabled] = useState(false);
  useEffect(() => {
    menuPortalTarget.current = document.body;
  }, []);

  const { changeAssignee } = useIncidentActions();
  const { data: users = [] } = useUsers();

  const assigneeOptions = useMemo(() => {
    const options = users
      .sort((a, b) => (a.name || a.email).localeCompare(b.name || b.email))
      .map((user) => ({
        value: user.email,
        label: (
          <div className="flex items-center gap-2">
            {user.picture ? (
              <img
                src={user.picture}
                alt={user.name || user.email}
                className="w-5 h-5 rounded-full"
              />
            ) : (
              <UserCircleIcon className="w-5 h-5 text-gray-400" />
            )}
            <span>{user.name || user.email}</span>
          </div>
        ),
      }));

    // Add "Unassigned" option at the beginning
    return [
      {
        value: null,
        label: (
          <div className="flex items-center gap-2">
            <UserCircleIcon className="w-5 h-5 text-gray-400" />
            <span className="text-gray-500">Unassigned</span>
          </div>
        ),
      },
      ...options,
    ];
  }, [users]);

  const handleChange = useCallback(
    (option: any) => {
      const _asyncUpdate = async (option: any) => {
        setIsDisabled(true);
        await changeAssignee(incidentId, option?.value || null);
        onChange?.(option?.value || null);
        setIsDisabled(false);
      };
      _asyncUpdate(option);
    },
    [incidentId, changeAssignee, onChange]
  );

  const selectedOption = useMemo(
    () => assigneeOptions.find((option) => option.value === value),
    [assigneeOptions, value]
  );

  // Find user for display
  const currentUser = users.find((u) => u.email === value);

  return (
    <Select
      instanceId={`incident-assignee-select-${incidentId}`}
      className={className}
      isSearchable={true}
      options={assigneeOptions}
      value={selectedOption}
      onChange={handleChange}
      isDisabled={isDisabled}
      placeholder={
        <div className="flex items-center gap-2">
          {currentUser?.picture ? (
            <img
              src={currentUser.picture}
              alt={currentUser.name || currentUser.email}
              className="w-5 h-5 rounded-full"
            />
          ) : (
            <UserCircleIcon className="w-5 h-5 text-gray-400" />
          )}
          <span className="text-gray-500">
            {value ? currentUser?.name || value : "Unassigned"}
          </span>
        </div>
      }
      classNames={customClassNames}
      menuPortalTarget={menuPortalTarget.current}
      menuPosition="fixed"
    />
  );
}
