"""Token counting with tiktoken and coarse fallback."""

import sys

try:
    import tiktoken

    _HAS_TIKTOKEN = True
except ImportError:
    _HAS_TIKTOKEN = False


class TokenCounter:
    """Count tokens in text using tiktoken or a coarse fallback.

    :param encoding_name: tiktoken encoding name (default cl100k_base).
    """

    def __init__(self, encoding_name: str = "cl100k_base") -> None:
        self.encoding_name = encoding_name
        self._encoder = None
        self._is_fallback = False

        if _HAS_TIKTOKEN:
            try:
                self._encoder = tiktoken.get_encoding(encoding_name)
            except Exception as exc:
                print(
                    f"WARNING: tiktoken encoding '{encoding_name}' failed: "
                    f"{exc}. Using coarse fallback (len//4).",
                    file=sys.stderr,
                )
                self._is_fallback = True
        else:
            print(
                "WARNING: tiktoken not installed. "
                "Using coarse fallback (len//4). "
                "Install with: uv sync --extra audit",
                file=sys.stderr,
            )
            self._is_fallback = True

    @property
    def is_fallback(self) -> bool:
        """True if using the coarse len//4 fallback."""
        return self._is_fallback

    @property
    def label(self) -> str:
        """Human-readable label for the encoding used."""
        if self._is_fallback:
            return "fallback (len//4)"
        return self.encoding_name

    def count(self, text: str) -> int:
        """Count tokens in text.

        :param text: Text to tokenize.
        :return: Token count.
        """
        if not text:
            return 0
        if self._encoder is not None:
            return len(self._encoder.encode(text))
        # Coarse fallback: ~4 chars per token on average for JSON
        return max(1, len(text) // 4)
