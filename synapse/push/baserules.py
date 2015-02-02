def make_base_rules(user_name):
    rules = [
        {
            'conditions': [
                {
                    'kind': 'event_match',
                    'key': 'content.body',
                    'pattern': '*%s*' % (user_name,), # Matrix ID match
                }
            ],
            'actions': [
                'notify',
                {
                    'set_sound': 'default'
                }
            ]
        },
        {
            'conditions': [
                {
                    'kind': 'contains_display_name'
                }
            ],
            'actions': [
                'notify',
                {
                    'set_sound': 'default'
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
                    'set_sound': 'default'
                }
            ]
        }
    ]
    for r in rules:
        r['priority_class'] = 0
    return rules