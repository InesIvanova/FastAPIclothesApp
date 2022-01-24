import math

FILE_PATH = "../../temp"


class SimpleMath:
    @staticmethod
    def my_first_method(a: int, b: int = 5) -> None:
        # This is needed because ...
        a = 6
        b = 7

        math.sqrt(a)

    def second_method(self) -> int:
        """
        This method represents the business logic for ...
        It integrates AWS for uploading big images to the bucket.
        ...
        """
        return 5


my_class = SimpleMath()
c = my_class.second_method()
c.upgrade({"a": 4})

a_var = 5
if a_var == 5:
    print("True")
