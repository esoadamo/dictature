from typing import List

from .mock import MockTransformer


class PipelineTransformer(MockTransformer):
    def __init__(self, transformers: List[MockTransformer]) -> None:
        self.__transformers = transformers

    def forward(self, text: str) -> str:
        for transformer in self.__transformers:
            text = transformer.forward(text)
        return text

    def backward(self, text: str) -> str:
        for transformer in reversed(self.__transformers):
            text = transformer.backward(text)
        return text

    @property
    def static(self) -> bool:
        return all(t.static for t in self.__transformers)
