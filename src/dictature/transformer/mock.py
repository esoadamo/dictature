
class MockTransformer:
    def forward(self, text: str) -> str:
        raise NotImplementedError("This method should be implemented by the child class")
    def backward(self, text: str) -> str:
        raise NotImplementedError("This method should be implemented by the child class")
