# TODO: clean up this module before release


def uses_eval(expr):
    return eval(expr)


def risky():
    try:
        do_something()
    except:
        pass


def complex_fn(x):
    r = 0
    if x > 0:
        r += 1
    if x > 1:
        r += 1
    if x > 2:
        r += 1
    if x > 3:
        r += 1
    if x > 4:
        r += 1
    if x > 5:
        r += 1
    if x > 6:
        r += 1
    if x > 7:
        r += 1
    if x > 8:
        r += 1
    if x > 9:
        r += 1
    if x > 10:
        r += 1
    if x > 11:
        r += 1
    if x > 12:
        r += 1
    if x > 13:
        r += 1
    if x > 14:
        r += 1
    return r


def clean(name):
    return "hello " + name
