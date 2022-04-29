## Code Free Contributions

###### ex. from Rapid7's Metasploit:

Before we get into the details of contributing code, you should know there are multiple ways you can add to Venom without any coding experience:

- You can [submit bugs and feature requests](https://github.com/V3n0m-Scanner/V3n0m-Scanner/issues/new/choose) with detailed information about your issue or idea:
  - If you'd like to propose a feature, describe what you'd like to see. Mock ups of console views would be great.
  - If you're reporting a bug, please be sure to include the expected behaviour, the observed behaviour, and steps to reproduce the problem. Resource scripts, console copy-pastes, and any background on the environment you encountered the bug in would be appreciated. More information can be found below.
- This can require technical knowledge, but you can also get involved in conversations about bug reports and feature requests. This is a great way to get involved without getting too overwhelmed!
- [Help fellow committers test recently submitted pull requests](https://github.com/V3n0m-Scanner/V3n0m-Scanner/pulls). Again this can require some technical skill, but by pulling down a pull request and testing it, you can help ensure our new code contributions for stability and quality.

## Code Contributions

For those of you who are looking to add code to Venom, your first step is to set up a [development environment].

#### <u>Pull Requests</u>

**Pull request [PR#203] is a good example to follow.**

- **Do** create a [topic branch] to work on instead of working directly on `master`. This helps to:
  - Protect the process.
  - Ensures users are aware of commits on the branch being considered for merge.
  - Allows for a location for more commits to be offered without mingling with other contributor changes.
  - Allows contributors to make progress while a PR is still being reviewed.
- **Do** follow the [50/72 rule] for Git commit messages.
- **Do** write "WIP" on your PR and/or open a [draft PR] if submitting **working** yet unfinished code.
- **Do** target your pull request to the **master branch**.
- **Do** specify a descriptive title to make searching for your pull request easier.
- **Do** include [console output], especially for effects that can be witnessed in the terminal.
- **Do** list [verification steps] so your code is testable.
- **Do** [reference associated issues] in your pull request description.
- **Don't** leave your pull request description blank.
- **Don't** abandon your pull request. Being responsive helps us land your code faster.
- **Don't** post questions in older closed PRs.
- **Do** license your code as GPLv3.
- **Do** stick to the [Python style guide] to find common style issues.

#### <u>Bug Fixes</u>

- **Do** include reproduction steps in the form of verification steps.
- **Do** link to any corresponding [Issues] in the format of `See #178` in your commit description.

When reporting Venom issues:

- **Do** write a detailed description of your bug and use a descriptive title.
- **Do** include reproduction steps, stack traces, and anything that might help us fix your bug.
- **Don't** file duplicate reports; search for your bug before filing a new report.
- **Don't** attempt to report issues on a closed PR.

Finally, **thank you** for taking the few moments to read this far! You're already way ahead of the
curve, so keep it up!

[help fellow users with open issues]: https://github.com/V3n0m-Scanner/V3n0m-Scanner/issues
[help fellow committers test recently submitted pull requests]: https://github.com/V3n0m-Scanner/V3n0m-Scanner/pulls
[development environment]: https://cloud.google.com/python/docs/setup
[python style guide]: https://www.python.org/dev/peps/pep-0008/
[50/72 rule]: http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html
[topic branch]: http://git-scm.com/book/en/Git-Branching-Branching-Workflows#Topic-Branches
[draft pr]: https://help.github.com/en/articles/about-pull-requests#draft-pull-requests
[console output]: https://docs.github.com/en/free-pro-team@latest/github/writing-on-github/creating-and-highlighting-code-blocks#fenced-code-blocks
[verification steps]: https://docs.github.com/en/free-pro-team@latest/github/writing-on-github/basic-writing-and-formatting-syntax#task-lists
[reference associated issues]: https://github.com/blog/1506-closing-issues-via-pull-requests
[pr#203]: https://github.com/v3n0m-Scanner/V3n0M-Scanner/pull/203
[issues]: https://github.com/V3n0m-Scanner/V3n0m-Scanner/issues
