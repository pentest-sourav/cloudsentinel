from engine.rules.model import RuleDefinition


class RuleRegistry:
    def __init__(self, rules: list[RuleDefinition]):
        self.rules = list(rules)
        self._rules_by_id = {}

        for rule in self.rules:
            if rule.rule_id in self._rules_by_id:
                raise ValueError(
                    f"Duplicate rule ID: {rule.rule_id}"
                )

            self._rules_by_id[rule.rule_id] = rule

    def list_rules(self) -> list[RuleDefinition]:
        return list(self.rules)

    def get_rule(self, rule_id: str) -> RuleDefinition:
        try:
            return self._rules_by_id[rule_id]
        except KeyError as exc:
            raise KeyError(
                f"Rule not found: {rule_id}"
            ) from exc

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)
