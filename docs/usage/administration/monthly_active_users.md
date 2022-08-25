# Monthly Active Users

Synapse can be configured to record the number of monthly active users (also referred to as MAU) on a given homeserver.
For clarity's sake, MAU only tracks local users.

Please note that the metrics recorded by the [Homeserver Usage Stats](/usage/administration/monitoriing/reporting_homeserver_usage_statistics)
are calculated differently. The `monthly_active_users` does not take into account any of the rules below, and counts any users 
who have made a request to the homeserver in the last 30 days.

See the [configuration manual](/usage/configuration/config_documentation.html#limit_usage_by_mau) for details on how to configure MAU.

## Calculating active users

Individual user activity is measured in active days, so if a user performs an action on a given day, that day is then recorded. When
calculating the MAU figure, any users with a recorded action in the last 30 days are considered part of the cohort.

A user is **never** considered active if they are either:
 - Part of the trial day cohort (described below)
 - Have an `appservice_id`.

Otherwise, any request to Synapse will mark the user as active. Internally, this is any request that records
the client's IP address into the database.

The MAU value is recalculated once every 5 minutes for active users, while inactive users are removed from the cohort once every hour.
Internally this works by checking all users, and adding any recently active users to the `monthly_active_users` table. Every hour, any
users with timestamps later than 30 days are removed. The sum of all rows of that table is the final count of active users.

### Trial days

If `mau_trial_days` is set, the user must have had activity at least this number of days apart for them to be considered part of the cohort.
As an example, if `mau_trial_days` is set to `2` and Alice is active on days 1,2 and 3 then they will be counted as an active user. If Bob
is active on days 1 and 2, then they will NOT be counted as active.

The `mau_appservice_trial_days` config further extends this rule by applying different durations depending on the appservice ID of the user.

It is important to note that **deactivated** users are not immediately removed from the pool of active users, but as blocked users won't
perform actions they will eventually be removed from the cohort.

## Limiting usage of the homeserver when the maximum MAU is reached

If both config options `limit_usage_by_mau` and `max_mau_value` is set, and the current MAU value exceeds the maximum value, the 
homeserver will begin to block some actions.

Individual users matching **any** of the below criteria never have their actions blocked:
  - Considered part of the cohort of MAU users.
  - Considered part of the trial period.
  - Registered as a `support` user. 

The following actions are blocked when the MAU limit is exceeded:
  - Logging in
  - Sending events
  - Creating rooms

Registration is also blocked for all new signups *unless* the user is registering with a threepid included in the `mau_limits_reserved_threepids`
config value. Users that register this way are also immediately considered active on that day.

When a request is blocked, the response will have the `errcode` `M_RESOURCE_LIMIT_EXCEEDED`.

## Metrics

Synapse records several different prometheus metrics for MAU.

`synapse_admin_mau:current` records the current MAU figure for native (non-appservice) users.

`synapse_admin_mau:max` records the maximum MAU as dictated by the `max_mau_value` config value.

`synapse_admin_mau_current_mau_by_service` records the current MAU including appservice users. This *also*
includes non-appservice users under the `native` label.

`synapse_admin_mau:registered_reserved_users` records the number of users specified in `mau_limits_reserved_threepids` which have
registered accounts on the homeserver.
