<h1 align="center">

[![License][license-badge]][license]
[![CI][build-badge]][build]
[![Latest release][latest-release-badge]][releases]
[![Project Chat][chat-badge]][chat-url]

[license-badge]: https://img.shields.io/github/license/prefix-dev/setup-pixi?style=flat-square
[license]: ./LICENSE
[build-badge]: https://img.shields.io/github/actions/workflow/status/prefix-dev/setup-pixi/test.yml?style=flat-square
[build]: https://github.com/prefix-dev/setup-pixi/actions/
[latest-release-badge]: https://img.shields.io/github/v/tag/prefix-dev/setup-pixi?style=flat-square&label=latest&sort=semver
[releases]: https://github.com/prefix-dev/setup-pixi/releases
[chat-badge]: https://img.shields.io/discord/1082332781146800168.svg?label=&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2&style=flat-square
[chat-url]: https://discord.gg/kKV8ZxyzY4

</h1>

# setup-pixi 📦

GitHub Action to set up the [pixi](https://github.com/prefix-dev/pixi) package manager.

## Usage

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  with:
    pixi-version: v0.20.0
    cache: true
    auth-host: prefix.dev
    auth-token: ${{ secrets.PREFIX_DEV_TOKEN }}
- run: pixi run test
```

> [!WARNING]
> Since pixi is not yet stable, the API of this action may change between minor versions.
> Please pin the versions of this action to a specific version (i.e., `prefix-dev/setup-pixi@v0.6.0`) to avoid breaking changes.
> You can automatically update the version of this action by using [Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot).
>
> Put the following in your `.github/dependabot.yml` file to enable Dependabot for your GitHub Actions:
>
> ```yml
> version: 2
> updates:
>   - package-ecosystem: github-actions
>     directory: /
>     schedule:
>       interval: monthly # or daily, weekly
>     groups:
>       dependencies:
>         patterns:
>           - "*"
> ```

## Features

To see all available input arguments, see the [`action.yml`](action.yml) file.

### Caching

The action supports caching of the pixi environment.
By default, caching is enabled if a `pixi.lock` file is present.
It will then use the `pixi.lock` file to generate a hash of the environment and cache it.
If the cache is hit, the action will skip the installation and use the cached environment.
You can specify the behavior by setting the `cache` input argument.

If you need to customize your cache-key, you can use the `cache-key` input argument.
This will be the prefix of the cache key. The full cache key will be `<cache-key><conda-arch>-<hash>`.

#### Only save caches on `main`

In order to not exceed the [10 GB cache size limit](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#usage-limits-and-eviction-policy) as fast, you might want to restrict when the cache is saved.
This can be done by setting the `cache-write` argument.

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  with:
    cache: true
    cache-write: ${{ github.event_name == 'push' && github.ref_name == 'main' }}
```

### Multiple environments

With pixi, you can create multiple environments for different requirements.
You can also specify which environment(s) you want to install by setting the `environments` input argument.
This will install all environments that are specified and cache them.

```toml
[project]
name = "my-package"
channels = ["conda-forge"]
platforms = ["linux-64"]

[dependencies]
python = ">=3.11"
pip = "*"
polars = ">=0.14.24,<0.21"

[feature.py311.dependencies]
python = "3.11.*"
[feature.py312.dependencies]
python = "3.12.*"

[environments]
py311 = ["py311"]
py312 = ["py312"]
```

#### Multiple environments using a matrix

The following example will install the `py311` and `py312` environments in different jobs.

```yml
test:
  runs-on: ubuntu-latest
  strategy:
    matrix:
      environment: [py311, py312]
  steps:
  - uses: actions/checkout@v4
  - uses: prefix-dev/setup-pixi@v0.6.0
    with:
      environments: ${{ matrix.environment }}
```

#### Install multiple environments in one job

The following example will install both the `py311` and the `py312` environment on the runner.

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  with:
    # separated by spaces
    environments: >-
      py311
      py312
- run: |
    pixi run -e py311 test
    pixi run -e py312 test
```

> [!WARNING]
> If you don't specify any environment, the `default` environment will be installed and cached, even if you use other environments.

### Authentication

There are currently three ways to authenticate with pixi:

- using a token
- using a username and password
- using a conda-token

For more information, see the [pixi documentation](https://prefix.dev/docs/pixi/authentication).

> [!WARNING]
> Please only store sensitive information using [GitHub secrets](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions). Do not store them in your repository.
> When your sensitive information is stored in a GitHub secret, you can access it using the `${{ secrets.SECRET_NAME }}` syntax.
> These secrets will always be masked in the logs.

#### Token

Specify the token using the `auth-token` input argument.
This form of authentication (bearer token in the request headers) is mainly used at [prefix.dev](https://prefix.dev).

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  with:
    auth-host: prefix.dev
    auth-token: ${{ secrets.PREFIX_DEV_TOKEN }}
```

#### Username and password

Specify the username and password using the `auth-username` and `auth-password` input arguments.
This form of authentication (HTTP Basic Auth) is used in some enterprise environments with [artifactory](https://jfrog.com/artifactory) for example.

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  with:
    auth-host: custom-artifactory.com
    auth-username: ${{ secrets.PIXI_USERNAME }}
    auth-password: ${{ secrets.PIXI_PASSWORD }}
```

#### Conda-token

Specify the conda-token using the `conda-token` input argument.
This form of authentication (token is encoded in URL: `https://my-quetz-instance.com/t/<token>/get/custom-channel`) is used at [anaconda.org](https://anaconda.org) or with [quetz instances](https://github.com/mamba-org/quetz).

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  with:
    auth-host: anaconda.org # or my-quetz-instance.com
    conda-token: ${{ secrets.CONDA_TOKEN }}
```

### Custom shell wrapper

`setup-pixi` allows you to run command inside of the pixi environment by specifying a custom shell wrapper with `shell: pixi run bash -e {0}`.
This can be useful if you want to run commands inside of the pixi environment, but don't want to use the `pixi run` command for each command.

```yml
- run: | # everything here will be run inside of the pixi environment
    python --version
    pip install --no-deps -e .
  shell: pixi run bash -e {0}
```

You can even run Python scripts like this:

```yml
- run: | # everything here will be run inside of the pixi environment
    import my_package
    print("Hello world!")
  shell: pixi run python {0}
```

If you want to use PowerShell, you need to specify `-Command` as well.
```yml
- run: | # everything here will be run inside of the pixi environment
    python --version | Select-String "3.11"
  shell: pixi run pwsh -Command {0} # pwsh works on all platforms
```

> [!NOTE]
> Under the hood, the `shell: xyz {0}` option is implemented by creating a temporary script file and calling `xyz` with that script file as an argument.
> This file does not have the executable bit set, so you cannot use `shell: pixi run {0}` directly but instead have to use `shell: pixi run bash {0}`.
> There are some custom shells provided by GitHub that have slightly different behavior, see [`jobs.<job_id>.steps[*].shell`](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsshell) in the documentation.
> See the [official documentation](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#custom-shell) and [ADR 0277](https://github.com/actions/runner/blob/main/docs/adrs/0277-run-action-shell-options.md) for more information about how the `shell:` input works in GitHub Actions.

### `--frozen` and `--locked`

You can specify whether `setup-pixi` should run `pixi install --frozen` or `pixi install --locked` depending on the `frozen` or the `locked` input argument.
See the [official documentation](https://prefix.dev/docs/pixi/cli#install) for more information about the `--frozen` and `--locked` flags.

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  with:
    locked: true
    # or
    frozen: true
```

If you don't specify anything, the default behavior is to run `pixi install --locked` if a `pixi.lock` file is present and `pixi install` otherwise.

### Debugging

There are two types of debug logging that you can enable.

#### Debug logging of the action

The first one is the debug logging of the action itself.
This can be enabled by running the action with the `RUNNER_DEBUG` environment variable set to `true`.

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  env:
    RUNNER_DEBUG: true
```

Alternatively, you can enable debug logging for the action by re-running the action in debug mode:

![Re-run in debug mode](.github/assets/enable-debug-logging-light.png#gh-light-mode-only)
![Re-run in debug mode](.github/assets/enable-debug-logging-dark.png#gh-dark-mode-only)

> For more information about debug logging in GitHub Actions, see [the official documentation](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/enabling-debug-logging).

#### Debug logging of pixi

The second type is the debug logging of the pixi executable.
This can be specified by setting the `log-level` input.

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  with:
    # one of `q`, `default`, `v`, `vv`, or `vvv`.
    log-level: vvv
```

If nothing is specified, `log-level` will default to `default` or `vv` depending on if [debug logging is enabled for the action](#debug-logging-of-the-action).

### Self-hosted runners

On self-hosted runners, it may happen that some files are persisted between jobs.
This can lead to problems or secrets getting leaked between job runs.
To avoid this, you can use the `post-cleanup` input to specify the post cleanup behavior of the action (i.e., what happens _after_ all your commands have been executed).

If you set `post-cleanup` to `true`, the action will delete the following files:

- `.pixi` environment
- the pixi binary
- the rattler cache
- other rattler files in `~/.rattler`

If nothing is specified, `post-cleanup` will default to `true`.

On self-hosted runners, you also might want to alter the default pixi install location to a temporary location. You can use `pixi-bin-path: ${{ runner.temp }}/bin/pixi` to do this.

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  with:
    post-cleanup: true
    # ${{ runner.temp }}\Scripts\pixi.exe on Windows
    pixi-bin-path: ${{ runner.temp }}/bin/pixi
```

You can also use a preinstalled local version of pixi on the runner by not setting any of the `pixi-version`,
`pixi-url` or `pixi-bin-path` inputs. This action will then try to find a local version of pixi in the runner's PATH.

### Using the `pyproject.toml` as a manifest file for pixi.

`setup-pixi` will automatically pick up the `pyproject.toml` if it contains a `[tool.pixi.project]` section and no `pixi.toml`.
This can be overwritten by setting the `manifest-path` input argument.

```yml
- uses: prefix-dev/setup-pixi@v0.6.0
  with:
    manifest-path: pyproject.toml
```

## More examples

If you want to see more examples, you can take a look at the [GitHub Workflows of this repository](.github/workflows/test.yml).

## Local Development

1. Clone this repository.
2. Run `pnpm install` inside the repository (if you don't have [`pnpm`](https://github.com/pnpm/pnpm) installed, you can install it with `pixi global install pnpm`).
3. Run `pnpm dev` for live transpilation of the TypeScript source code. 
4. To test the action, you can run [`act`](https://github.com/nektos/act) (inside docker) or use :sparkles: CI driven development :sparkles:.
