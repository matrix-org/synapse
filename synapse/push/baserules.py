from synapse.push.rulekinds import PRIORITY_CLASS_MAP, PRIORITY_CLASS_INVERSE_MAP


def list_with_base_rules(rawrules, user_name):
    ruleslist = []

    # shove the server default rules for each kind onto the end of each
    current_prio_class = PRIORITY_CLASS_INVERSE_MAP.keys()[-1]
    for r in rawrules:
        if r['priority_class'] < current_prio_class:
            while r['priority_class'] < current_prio_class:
                ruleslist.extend(make_base_rules(
                    user_name,
                    PRIORITY_CLASS_INVERSE_MAP[current_prio_class]
                ))
                current_prio_class -= 1

        ruleslist.append(r)

    while current_prio_class > 0:
        ruleslist.extend(make_base_rules(
            user_name,
            PRIORITY_CLASS_INVERSE_MAP[current_prio_class]
        ))
        current_prio_class -= 1

    return ruleslist


def make_base_rules(user, kind):
    rules = []

    if kind == 'override':
        rules = make_base_override_rules()
    elif kind == 'content':
        rules = make_base_content_rules(user)

    for r in rules:
        r['priority_class'] = PRIORITY_CLASS_MAP[kind]
        r['default'] = True

    return rules


def make_base_content_rules(user):
    return [
        {
            'conditions': [
                {
                    'kind': 'event_match',
                    'key': 'content.body',
                    'pattern': user.localpart,  # Matrix ID match
                }
            ],
            'actions': [
                'notify',
                {
                    'set_tweak': 'sound',
                    'value': 'default',
                }
            ]
        },
    ]


def make_base_override_rules():
    return [
        {
            'conditions': [
                {
                    'kind': 'contains_display_name'
                }
            ],
            'actions': [
                'notify',
                {
                    'set_tweak': 'sound',
                    'value': 'default'
                }
            ]
        },
        {
            'conditions': [
                {
                    'kind': 'room_member_count',
                    'is': '2'
                }
            ],
            'actions': [
                'notify',
                {
                    'set_tweak': 'sound',
                    'value': 'default'
                }
            ]
        }
    ]
