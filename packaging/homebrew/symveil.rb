# Manual formula for https://github.com/magnusmalm/homebrew-symveil
#
# The v* release workflow generates this formula with real checksums and
# pushes it to the tap when HOMEBREW_TAP_TOKEN is set. Use this copy only
# if you publish the formula yourself. Replace every sha256 line with the
# digest from the matching .sha256 asset on the v0.1.0 GitHub Release
# before committing it to the tap. See RELEASING.md.
class Symveil < Formula
  desc "Local secret-masking proxy between coding agents and cloud LLMs"
  homepage "https://symveil.dev"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/magnusmalm/symveil/releases/download/v0.1.0/symveil-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_THE_GITHUB_RELEASE"
    end
    if Hardware::CPU.intel?
      url "https://github.com/magnusmalm/symveil/releases/download/v0.1.0/symveil-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_THE_GITHUB_RELEASE"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/magnusmalm/symveil/releases/download/v0.1.0/symveil-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_THE_GITHUB_RELEASE"
    end
    if Hardware::CPU.intel?
      url "https://github.com/magnusmalm/symveil/releases/download/v0.1.0/symveil-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_THE_GITHUB_RELEASE"
    end
  end

  def install
    bin.install "symveil"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/symveil --version")
  end
end
