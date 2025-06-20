import yara

def run_yara_scan(file_path, rule_path='data/yara_rules.yar'):
    rules = yara.compile(filepath=rule_path)
    matches = rules.match(filepath=file_path)
    return [match.rule for match in matches]
