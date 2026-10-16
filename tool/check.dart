// Runs package checks from the repository root, stopping at the first failure.
// Usage: dart tool/check.dart
import 'dart:io';

const _steps = [
  // Also resolves example/.
  ('.', ['pub', 'get']),
  (
    '.',
    [
      'format',
      '--output=none',
      '--set-exit-if-changed',
      'lib',
      'test',
      'tool',
      'example',
    ],
  ),
  ('.', ['analyze', '--fatal-infos']),
  ('.', ['test', '--reporter', 'expanded']),
  ('example', ['test', '--reporter', 'expanded', 'integration_test']),
  ('.', ['pub', 'publish', '--dry-run']),
];

Future<void> main() async {
  final dart = Platform.resolvedExecutable;
  final root = File.fromUri(Platform.script).parent.parent;
  for (final (directory, step) in _steps) {
    final command = 'dart ${step.join(' ')}';
    stdout.writeln(
      directory == '.' ? '\$ $command' : '\$ (cd $directory) $command',
    );
    final process = await Process.start(
      dart,
      step,
      workingDirectory: root.uri.resolve(directory).toFilePath(),
      mode: ProcessStartMode.inheritStdio,
    );
    final code = await process.exitCode;
    if (code != 0) {
      stderr.writeln('Check failed: $command (exit $code)');
      exit(code);
    }
  }
}
