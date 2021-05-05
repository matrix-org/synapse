Add limits to how often Synapse will GC, ensuring that large servers do not end up GC thrashing if `gc_thresholds` has not been correctly set.
