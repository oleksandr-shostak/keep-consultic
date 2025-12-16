import { Button } from "@tremor/react";
import {
  RuleGroupProps as QueryRuleGroupProps,
  RuleGroupType,
  RuleType,
} from "react-querybuilder";
import { RuleFields } from "./RuleFields";

export const RuleGroup = ({ actions, ruleGroup }: QueryRuleGroupProps) => {
  const { onRuleAdd, onGroupAdd, onRuleRemove, onPropChange } = actions;
  const { rules } = ruleGroup;

  const onAddGroupClick = () => {
    // The UI renders groups as being combined by OR. Ensure the underlying query
    // matches that so we don't serialize `&&` while displaying "OR".
    onPropChange("combinator", "or", []);
    return onGroupAdd(
      {
        combinator: "and",
        rules: [{ field: "severity", operator: "=", value: "" }],
      },
      []
    );
  };

  return (
    <div className="space-y-2">
      {rules.map((rule, groupIndex) =>
        // we only want rule groups to be rendered
        typeof rule === "object" && "combinator" in rule ? (
          <div key={groupIndex}>
            <div className="mb-2">
              {groupIndex > 0
                ? String(ruleGroup.combinator ?? "or").toUpperCase()
                : ""}
            </div>
            <RuleFields
              rule={
                rule as RuleGroupType<
                  RuleType<string, string, any, string>,
                  string
                >
              }
              key={rule.id}
              groupIndex={groupIndex}
              onRuleAdd={onRuleAdd}
              onRuleRemove={onRuleRemove}
              onPropChange={onPropChange}
              query={ruleGroup}
              groupsLength={rules.length}
            />
          </div>
        ) : null
      )}
      <Button
        className="mt-3"
        onClick={onAddGroupClick}
        type="button"
        variant="light"
        color="orange"
      >
        Add filter
      </Button>
    </div>
  );
};
