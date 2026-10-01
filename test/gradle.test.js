import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseGradle, blankComments } from '../src/index.js';
import { check, manifest, find } from './helpers.js';

const KOTLIN = `android {
    namespace = "com.example.orders"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.example.orders"
        minSdk = 24
        targetSdk = 34
    }
    signingConfigs {
        create("release") {
            enableV1Signing = true
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
        }
        debug {
            isDebuggable = true
        }
    }
}
`;

const GROOVY = `android {
    compileSdkVersion 34
    defaultConfig {
        minSdkVersion 23
        targetSdkVersion 30
    }
    buildTypes {
        release {
            minifyEnabled false
            debuggable true
        }
    }
}
`;

test('parseGradle reads the Kotlin DSL: SDK levels, namespace and the release build type only', () => {
  const g = parseGradle(KOTLIN, 'build.gradle.kts');
  assert.equal(g.kotlin, true);
  assert.deepEqual([g.minSdk.value, g.targetSdk.value, g.compileSdk.value], [24, 34, 35]);
  assert.deepEqual([g.minSdk.line, g.targetSdk.line, g.compileSdk.line], [6, 7, 3]);
  assert.equal(g.namespace, 'com.example.orders');
  assert.equal(g.applicationId, 'com.example.orders');
  assert.equal(g.release.line, 15, 'the release block under buildTypes, not the signing config');
  assert.deepEqual(g.release.minify, { value: true, line: 16 });
  assert.equal(g.release.debuggable, null, 'isDebuggable in the debug block does not count');
  assert.deepEqual(g.notes, []);
});

test('parseGradle reads the Groovy DSL with the older names', () => {
  const g = parseGradle(GROOVY, 'build.gradle');
  assert.equal(g.kotlin, false);
  assert.deepEqual([g.minSdk.value, g.targetSdk.value, g.compileSdk.value], [23, 30, 34]);
  assert.deepEqual(g.release.minify, { value: false, line: 9 });
  assert.deepEqual(g.release.debuggable, { value: true, line: 10 });
});

test('parseGradle ignores comments, notes expressions and repeated settings, and reads getByName("release")', () => {
  const text = [
    '// targetSdk = 19',
    '/* minSdk = 15',
    '   still a comment */',
    'android {',
    '    defaultConfig { targetSdk = libs.versions.target.get().toInt() }',
    '    minSdk = 21 // the lowest',
    '    minSdk = 26',
    '    val url = "https://example.test//path"',
    '    buildTypes {',
    '        getByName("release") {',
    '            isMinifyEnabled = false',
    '        }',
    '    }',
    '}'
  ].join('\n');
  assert.equal(blankComments('a // b\nc /* d\ne */ f').split('\n').length, 3);
  assert.equal(blankComments('"x // y"'), '"x // y"', 'a // inside a string is not a comment');
  const g = parseGradle(text, 'build.gradle.kts');
  assert.equal(g.minSdk.value, 21);
  assert.equal(g.minSdk.line, 6);
  assert.equal(g.targetSdk, null, 'defaultConfig { targetSdk = ... } on one line is not at the start of a line');
  assert.ok(g.notes.some((n) => /minSdk is set 2 times/.test(n)));
  assert.deepEqual(g.release.minify, { value: false, line: 11 });
  const expr = parseGradle('android {\n  targetSdk = libs.versions.target.get().toInt()\n}\n', 'build.gradle.kts');
  assert.equal(expr.targetSdk.value, null);
  assert.match(expr.notes[0], /line 2: targetSdk is set from an expression/);
});

test('minify-off and debuggable from the build file; targetSdk in the build file wins over <uses-sdk>', async () => {
  const files = {
    'AndroidManifest.xml': manifest({ top: '<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="35" />' }),
    'build.gradle': GROOVY
  };
  const r = await check(files, { android: 'AndroidManifest.xml', gradle: 'build.gradle' });
  assert.deepEqual(find(r, 'minify-off').map((f) => [f.severity, f.file, f.line]), [['info', 'build.gradle', 9]]);
  assert.deepEqual(find(r, 'debuggable').map((f) => [f.severity, f.file, f.line]), [['error', 'build.gradle', 10]]);
  assert.deepEqual(find(r, 'target-sdk').map((f) => [f.file, f.line, f.subject]), [['build.gradle', 5, 'targetSdk 30']]);
  assert.ok(r.notes.some((n) => /sets targetSdkVersion 35, but .*build\.gradle sets 30; the build file wins/.test(n)));
  const shrunk = await check({ 'AndroidManifest.xml': files['AndroidManifest.xml'], 'build.gradle.kts': KOTLIN }, { android: 'AndroidManifest.xml', gradle: 'build.gradle.kts' });
  assert.equal(find(shrunk, 'minify-off').length, 0);
  assert.equal(find(shrunk, 'debuggable').length, 0);
  const none = await check({ 'AndroidManifest.xml': files['AndroidManifest.xml'], 'build.gradle.kts': 'android {\n  compileSdk = 35\n}\n' }, { android: 'AndroidManifest.xml', gradle: 'build.gradle.kts' });
  assert.match(find(none, 'minify-off')[0].message, /there is no release build type/);
});
