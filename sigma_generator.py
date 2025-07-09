import uuid
import datetime

def generate_sigma(use_case_description, attack_technique="T1059.001"):
    title = f"Detection for: {use_case_description[:40]}..."
    sigma_id = str(uuid.uuid4())
    date = datetime.datetime.utcnow().strftime("%Y-%m-%d")

    rule = f"""
title: {title}
id: {sigma_id}
description: Automatically generated rule for: {use_case_description}
status: experimental
date: {date}
author: NaradMuni AI
logsource:
  product: windows
  service: security
detection:
  selection:
    CommandLine|contains: '{use_case_description.split()[0]}'
  condition: selection
fields:
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Legitimate admin tools
level: medium
tags:
  - attack.{attack_technique}
"""
    return rule.strip()
