# PROOF FIXTURE, never merged. A parameter reaches eval: the library threat model must report line 3.
def evaluate(expression):
    return eval(expression)


# Negative control: a closed set, so this must stay silent.
def evaluate_known(name):
    assert name in ("alpha", "beta")
    return eval(name)
