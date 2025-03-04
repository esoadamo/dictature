
class MockTransformer:
    def forward(self, text: str) -> str:
        """
        Transform the text in some way to the data format in data storage
        :param text: text to transform
        :return: transformed text
        """
        raise NotImplementedError("This method should be implemented by the child class")

    def backward(self, text: str) -> str:
        """
        Transform the data format in data storage to the text
        :param text: text to transform
        :return: original text
        """
        raise NotImplementedError("This method should be implemented by the child class")

    @property
    def static(self) -> bool:
        """
        Returns True only if when the forward transformation is applied to the same text, the result is always the same
        :return: True if the transformation is static
        """
        raise NotImplementedError("This method should be implemented by the child class")
