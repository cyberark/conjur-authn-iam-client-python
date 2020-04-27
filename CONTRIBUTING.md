# Contributing

For general contribution and community guidelines, please see the [community repo](https://github.com/cyberark/community).

## Table of Contents

- [Development](#development)
- [Testing](#testing)
- [Releases](#releases)
- [Contributing](#contributing-workflow)

## Development

- Python3.6 or greater
- Valid AWS IAM credentials

## Testing

Currently all tests are done manually.

## Releases

Our release process generally follows this pattern for most projects:

1. The maintainers agree that a release should be made from current work on default branch. This
   may include 1 or more individuals and can include input from project management, product
   management, technical writers, infrastructure, etc.
2. [**Annotated** git tag is created](https://github.com/cyberark/community/blob/master/Conjur/CONTRIBUTING.md#tagging).
3. [Draft release is created](https://github.com/cyberark/community/blob/master/Conjur/CONTRIBUTING.md#draft-release-creation) from that tag.
4. After some local smoke testing, a [pre-release is published](https://github.com/cyberark/community/blob/master/Conjur/CONTRIBUTING.md#pre-release-publishing).
5. Finally, after some project-dependent amount of user testing, the pre-release is then
   [published as a regular release](https://github.com/cyberark/community/blob/master/Conjur/CONTRIBUTING.md#release-publishing).


## Contributing workflow

1. [Fork the project](https://help.github.com/en/github/getting-started-with-github/fork-a-repo)
2. [Clone your fork](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository)
3. Make local changes to your fork by editing files
3. [Commit your changes](https://help.github.com/en/github/managing-files-in-a-repository/adding-a-file-to-a-repository-using-the-command-line)
4. [Push your local changes to the remote server](https://help.github.com/en/github/using-git/pushing-commits-to-a-remote-repository)
5. [Create new Pull Request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request-from-a-fork)

From here your pull request will be reviewed and once you've responded to all
feedback it will be merged into the project. Congratulations, you're a
contributor!