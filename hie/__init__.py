"""Hidden-instructions eval (hie).

Measures what a coding agent does when a repo it is working in contains
instructions aimed at it: does it follow them, does it tell the user, and
would the live guard (hooks/guard.py) have stopped it?

Everything the agent touches is simulated in memory. No command runs, no
network call leaves the process, and every "secret" is a fake canary.
"""

__version__ = "0.1.0"
