"""Safe, synthetic incident simulator.

Everything here runs the *real* detection pipeline against generated data,
inside a throw-away SQLite database in a temporary directory, with AWS and
email forced off. Nothing is read from or written to the dashboard's own
database, log files, or any external system.
"""
