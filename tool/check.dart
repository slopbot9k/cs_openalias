// Runs package checks from the repository root, stopping at the first failure.
// Usage: dart tool/check.dart
import 'dart:io';

const _steps = [
  ['pub', 'get', '--no-example'],
  [
    'format',
    '--output=none',
    '--set-exit-if-changed',
    'lib',
    'test',
    'tool',
    'example',
  ],
  ['analyze', '--fatal-infos'],
  ['test', '--reporter', 'expanded'],
  ['pub', 'publish', '--dry-run'],
];

Future<void> main() async {
  final dart = Platform.resolvedExecutable;
  final root = File.fromUri(Platform.script).parent.parent.path;
  for (final step in _steps) {
    stdout.writeln('\$ dart ${step.join(' ')}');
    final process = await Process.start(
      dart,
      step,
      workingDirectory: root,
      mode: ProcessStartMode.inheritStdio,
    );
    final code = await process.exitCode;
    if (code != 0) {
      stderr.writeln('Check failed: dart ${step.join(' ')} (exit $code)');
      exit(code);
    }
  }
}
