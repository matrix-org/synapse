def make_base_rules(user_name):
    """
    Nominally we reserve priority class 0 for these rules, although
    in practice we just append them to the end so we don't actually need it.
    """
    return [
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
    ]