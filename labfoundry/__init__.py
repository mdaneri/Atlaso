"""LabFoundry appliance application package."""

__all__ = ["__version__", "__build_git_commit__", "__build_time_utc__"]

try:
    from labfoundry._build import BUILD_TIME_UTC, BUILD_VERSION, GIT_COMMIT
except ImportError:
    BUILD_TIME_UTC = ""
    BUILD_VERSION = "0.9.7"
    GIT_COMMIT = ""

__version__ = BUILD_VERSION
__build_git_commit__ = GIT_COMMIT
__build_time_utc__ = BUILD_TIME_UTC
