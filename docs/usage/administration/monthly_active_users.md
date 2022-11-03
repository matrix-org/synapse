# Monthly Active Users

Synapse can be configured to record the number of monthly active users (also referred to as MAU) on a given homeserver.
For clarity's sake, MAU only tracks local users.

Please note that the metrics recorded by the [Homeserver Usage Stats](../../usage/administration/monitoring/reporting_homeserver_usage_statistics.md)
are calculated differently. The `monthly_active_users` from the usage stats does not take into account any
of the rules below, and counts any users who have made a request to the homeserver in the last 30 days.

See the [configuration manual](../../usage/configuration/config_documentation.md#limit_usage_by_mau) for details on how to configure MAU.

## Calculating active users

Individual user activity is measured in active days. If a user performs an action, the exact time of that action is then recorded. When
calculating the MAU figure, any users with a recorded action in the last 30 days are considered part of the cohort. Days are measured
as a rolling window from the current system time to 30 days ago.

So for example, if Synapse were to calculate the active users on the 15th July at 13:25, it would include any activity from 15th June 13:25 onwards.

A user is **never** considered active if they are either:
 - Part of the trial day cohort (described below)
 - Owned by an application service.
   - Note: This **only** covers users that are part of an application service `namespaces.users` registration. The namespace
     must also be marked as `exclusive`.

Otherwise, any request to Synapse will mark the user as active. Please note that registration will not mark a user as active *unless* 
they register with a 3pid that is included in the config field `mau_limits_reserved_threepids`.

The Prometheus metric for MAU is refreshed every 5 minutes.

Once an hour, Synapse checks to see if any users are inactive (with only activity timestamps later than 30 days). These users
are removed from the active users cohort. If they then become active, they are immediately restored to the cohort.

It is important to note that **deactivated** users are not immediately removed from the pool of active users, but as these users won't
perform actions they will eventually be removed from the cohort.

### Trial days

If the config option `mau_trial_days` is set, a user must have been active this many days **after** registration to be active. A user is in the
trial period if their registration timestamp (also known as the `creation_ts`) is less than `mau_trial_days` old.

As an example, if `mau_trial_days` is set to `3` and a user is active **after** 3 days (72 hours from registration time) then they will be counted as active.

The `mau_appservice_trial_days` config further extends this rule by applying different durations depending on the `appservice_id` of the user.
Users registered by an application service will be recorded with an `appservice_id` matching the `id` key in the registration file for that service.


## Limiting usage of the homeserver when the maximum MAU is reached

If both config options `limit_usage_by_mau` and `max_mau_value` is set, and the current MAU value exceeds the maximum value, the 
homeserver will begin to block some actions.

Individual users matching **any** of the below criteria never have their actions blocked:
  - Considered part of the cohort of MAU users.
  - Considered part of the trial period.
  - Registered as a `support` user.
  - Application service users if `track_appservice_user_ips` is NOT set.

Please not that server admins are **not** exempt from blocking.

The following actions are blocked when the MAU limit is exceeded:
  - Logging in
  - Sending events
  - Creating rooms
  - Syncing

Registration is also blocked for all new signups *unless* the user is registering with a threepid included in the `mau_limits_reserved_threepids`
config value.

When a request is blocked, the response will have the `errcode` `M_RESOURCE_LIMIT_EXCEEDED`.

## Metrics

Synapse records several different prometheus metrics for MAU.

`synapse_admin_mau_current` records the current MAU figure for native (non-application-service) users.

`synapse_admin_mau_max` records the maximum MAU as dictated by the `max_mau_value` config value.

`synapse_admin_mau_current_mau_by_service` records the current MAU including application service users. The label `app_service` can be used
to filter by a specific service ID. This *also* includes non-application-service users under `app_service=native` .

`synapse_admin_mau_registered_reserved_users` records the number of users specified in `mau_limits_reserved_threepids` which have
registered accounts on the homeserver.
