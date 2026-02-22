class IcaCli < Formula
  include Language::Python::Virtualenv

  desc "ICA grocery CLI for automation"
  homepage "https://github.com/liamvinberg/ica-cli"
  url "https://github.com/liamvinberg/ica-cli/releases/download/v0.1.0/ica-cli-0.1.0.tar.gz"
  sha256 "e50af1b1020c69f596fc98c32e86c8080c08027599a72b0887dc3bf0b052eca9"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    output = shell_output("#{bin}/ica --json config show")
    assert_match "provider", output
  end
end
