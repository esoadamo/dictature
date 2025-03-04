from .mock import MockTransformer


class PassthroughTransformer(MockTransformer):
    """
    Passthrough transformer, does not modify the text.
    """

    def forward(self, text: str) -> str:
        return text

    def backward(self, text: str) -> str:
        return text

    @property
    def static(self) -> bool:
        return True
