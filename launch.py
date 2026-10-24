"""Source/bundle entry point; check Python before importing the application."""
import json
import sys


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if sys.version_info < (3, 11):
        if '--doctor' in args:
            print(json.dumps({'schema_version': 'artemis-environment/1', 'status': 'failed',
                              'error_code': 'python_3_11_or_newer_required'}))
        else:
            print('Artemis v3 requires Python 3.11 or newer. See FIRST_TEST.md.', file=sys.stderr)
        return 2
    try:
        from artemis_v3.deployment import main as run
    except ImportError:
        print('Application files are incomplete. Extract the full package and see FIRST_TEST.md.', file=sys.stderr)
        return 2
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
