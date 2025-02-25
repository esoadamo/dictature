from .mock import MockTransformer

class PassthroughTransformer(MockTransformer):
    def forward(self, text: str) -> str:
        return text
    def backward(self, text: str) -> str:
        return text
