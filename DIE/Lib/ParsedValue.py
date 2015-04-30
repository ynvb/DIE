
MAX_SCORE = 10


class ParsedValue():
    """
    Possible run-time value.
    The value data might either be definite or guessed.
    """

    def __init__(self, data, description, score=0, raw=None, type_=None):
        """
        Ctor
        @param data:  The data`s human-readable representation.
        @param description: A description string for the value data type
        @param score: score is a (0-10) value indicating the probability of the value.
               score of 0 (default) means the value is certain
        """
        self.data = data
        self.description = description
        self.type = type_
        self.raw = raw  # TODO: Validate value is a string (representing hex values)

        # If score cannot be validated set its value to 10 (Guessed).
        if self._validate_score(score):
            self.score = score
        else:
            self.score = MAX_SCORE

    def _validate_score(self, score):
        """
        Validate that score value is in range 0-10.
        @param score: Score value to validate
        @return: True if score is valid, otherwise False.
        """
        return 0 <= score <= MAX_SCORE

    def is_guessed(self):
        """
        Check if the value is guessed
        @return: True if the value is guessed, otherwise False
        """

        return not self.score == 0