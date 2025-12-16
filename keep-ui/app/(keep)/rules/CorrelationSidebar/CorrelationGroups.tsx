import QueryBuilder from "react-querybuilder";
import { RuleGroup } from "./RuleGroup";
import { Controller, useFormContext } from "react-hook-form";
import { Button } from "@tremor/react";
import { QuestionMarkCircleIcon } from "@heroicons/react/24/outline";
import { CorrelationFormType } from "./types";

export const CorrelationGroups = () => {
  const { control } = useFormContext<CorrelationFormType>();

  return (
    <div>
      <div className="flex justify-between items-center">
        <p className="text-tremor-default font-medium text-tremor-content-strong mb-2">
          Add filters
        </p>

        <Button
          className="cursor-default"
          type="button"
          tooltip="A correlation can include one or more alert groups. Conditions within a group are combined with AND, and groups are combined with OR."
          icon={QuestionMarkCircleIcon}
          size="xs"
          variant="light"
          color="slate"
        />
      </div>
      <Controller
        control={control}
        name="query"
        render={({ field: { value, onChange } }) => (
          <QueryBuilder
            query={value}
            onQueryChange={onChange}
            addRuleToNewGroups
            controlElements={{
              ruleGroup: RuleGroup,
            }}
          />
        )}
      />
    </div>
  );
};
