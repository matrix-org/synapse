What do I do about "Unexpected logging context" debug log-lines everywhere?

<Mjark> The logging context lives in thread local storage
<Mjark> Sometimes it gets out of sync with what it should actually be, usually because something scheduled something to run on the reactor without preserving the logging context. 
<Matthew> what is the impact of it getting out of sync? and how and when should we preserve log context?
<Mjark> The impact is that some of the CPU and database metrics will be under-reported, and some log lines will be mis-attributed.
<Mjark> It should happen auto-magically in all the APIs that do IO or otherwise defer to the reactor.
<Erik> Mjark: the other place is if we branch, e.g. using defer.gatherResults

Unanswered: how and when should we preserve log context?