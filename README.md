# setup-pixi 📦

[![CI](https://github.com/pavelzw/setup-pixi/actions/workflows/test.yml/badge.svg)](https://github.com/pavelzw/setup-pixi/actions/workflows/test.yml)

GitHub Action to set up the [pixi](https://github.com/prefix-dev/pixi) package manager.

## Usage

```yml
- uses: pavelzw/setup-pixi@v0.1.2
  with:
    pixi-version: '0.2.0'
    cache: true
    auth-host: prefix.dev
    auth-token: ${{ secrets.PREFIX_DEV_TOKEN }}
- run: pixi run test
```

## Features

To see all available input arguments, see the [`action.yml`](action.yml) file.

### Caching

The action supports caching of the pixi environment. To enable caching, set `cache: true`.
It will then use the `pixi.lock` file to generate a hash of the environment and cache it.
If the cache is hit, the action will skip the installation and use the cached environment.

If you need to customize your cache-key, you can use the `cache-key` input argument.
This will be the prefix of the cache key. The full cache key will be `<cache-key><conda-arch>-<hash>`.

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
- uses: pavelzw/setup-pixi@v0.1.2
  with:
    auth-host: prefix.dev
    auth-token: ${{ secrets.PREFIX_DEV_TOKEN }}
```

#### Username and password

Specify the username and password using the `auth-username` and `auth-password` input arguments.
This form of authentication (HTTP Basic Auth) is used in some enterprise environments with [artifactory](https://jfrog.com/artifactory) for example.

```yml
- uses: pavelzw/setup-pixi@v0.1.2
  with:
    auth-host: custom-artifactory.com
    auth-username: ${{ secrets.PIXI_USERNAME }}
    auth-password: ${{ secrets.PIXI_PASSWORD }}
```

#### Conda-token

Specify the conda-token using the `conda-token` input argument.
This form of authentication (token is encoded in URL: `https://my-quetz-instance.com/t/<token>/get/custom-channel`) is used at [anaconda.org](https://anaconda.org) or with [quetz instances](https://github.com/mamba-org/quetz).

```yml
- uses: pavelzw/setup-pixi@v0.1.2
  with:
    auth-host: anaconda.org # or my-quetz-instance.com
    conda-token: ${{ secrets.CONDA_TOKEN }}
```

### Custom shell wrapper

`setup-pixi` allows you to run command inside of the pixi environment by specifying a custom shell wrapper with `shell: pixi run bash {0}`.
This can be useful if you want to run commands inside of the pixi environment, but don't want to use the `pixi run` command for each command.

```yml
- run: | # everything here will be run inside of the pixi environment
    python --version
    pip install -e --no-deps .
  shell: pixi run bash {0}
```

You can even run python scripts like this:

```yml
- run: | # everything here will be run inside of the pixi environment
    import my_package
    print("Hello world!")
  shell: pixi run python {0}
```

> [!NOTE]
> Under the hood, the `shell: xyz {0}` option is implemented by creating a temporary script file and calling `xyz` with that script file as an argument.
> This file does not have the executable bit set, so you cannot use `shell: pixi run {0}` directly but instead have to use `shell: pixi run bash {0}`.
> See the [official documentation](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#custom-shell) and [ADR 0277](https://github.com/actions/runner/blob/main/docs/adrs/0277-run-action-shell-options.md) for more information about how the `shell:` input works in GitHub Actions.

### Debugging

There are two types of debug logging that you can enable.

#### Debug logging of the action

The first one is the debug logging of the action itself.
This can be enabled by running the action with the `RUNNER_DEBUG` environment variable set to `true`.

```yml
- uses: pavelzw/setup-pixi@v0.1.2
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
- uses: pavelzw/setup-pixi@v0.1.2
  with:
    # one of `q`, `default`, `v`, `vv`, or `vvv`.
    log-level: vv
```

If nothing is specified, `setup-pixi` will default to `default` or `debug` depending on if [debug logging is enabled for the action](#debug-logging-of-the-action).

### Post action cleanup

On self hosted runners, it may happen that some files are persisted between jobs.
This can lead to problems or secrets getting leaked between job runs.
To avoid this, you can use the `post-cleanup` input to specify the post cleanup behavior of the action (i.e., what happens _after_ all your commands have been executed).

If you set `post-cleanup` to `true`, the action will delete the following files:

- `.pixi` environment
- the pixi binary
- the rattler cache
- other rattler files in `~/.rattler`

If nothing is specified, `setup-pixi` will default to `true`.

```yml
- uses: pavelzw/setup-pixi@v0.1.2
  with:
    post-cleanup: false
```

## More examples

If you want to see more examples, you can take a look at the [GitHub Workflows of this repository](.github/workflows/test.yml).

## Local Development

1. Clone this repository.
1. Run `pnpm install` inside the repository (if you don't have [`pnpm`](https://github.com/pnpm/pnpm) installed, you can install it with `npm install -g pnpm` or `brew install pnpm`).
1. Run `pnpm dev` for live transpilation of the TypeScript source code.
1. To test the action, you can run [`act`](https://github.com/nektos/act) (inside docker) or use :sparkles: CI driven development :sparkles:.
