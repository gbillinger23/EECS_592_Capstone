import os
import yaml

class Rule:
    def __init__(self, id, description, severity, conditions, window=None, tags=None):
        self.id = id
        self.description = description
        self.severity = severity
        self.conditions = conditions
        self.window = window
        self.tags = []

    def __str__(self):
        return self.id

def load_rules(rules_directory="./rules"):
    rules = []

    # Iterate through each rule file
    for file in os.listdir(rules_directory):
        if not file.endswith(".yaml"): # If not a rule file, skip!
            continue
            
        path = os.path.join(rules_directory, file) # Get rule file path.

        with open(path, "r") as f: # Open the rule file and load its data.
            data = yaml.safe_load(f)

        # Validate all fields exist in rule file.
        required = ["id", "description", "severity", "conditions"]
        for field in required:
            if field not in data:
                raise ValueError(f"Rule {file} missing required field: {field}")
                
        # Synthesize conditions
        all_conds = []
        for cond in data["conditions"]:
            all_conds.append({
                "field": cond["field"],
                "operator": cond["operator"],
                "value": cond["value"]
            })

        # Put data into rule object
        rule = Rule(
            id=data["id"],
            description=data["description"],
            severity=data["severity"],
            conditions=all_conds,
            window=data.get("window"),
            tags=data.get("tags", [])
        )

        rules.append(rule)

    return rules

''' LOAD RULES DEBUG
r = load_rules()

for i in r:
    print(i)
'''