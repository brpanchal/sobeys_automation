
def mock_cd_rewind(x, y):
    print("mock_cd_rewind")

def mock_cd_rewind_exception(x, y):
    print("mock_cd_rewind_exception")
    raise Exception("Unexpected exception found during execution: boom")