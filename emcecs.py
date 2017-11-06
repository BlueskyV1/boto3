from emcboto3.session import Session

def custom_method(self):
    print("custom method added")

def add_custom_method(class_attributes, **kwargs):
    class_attributes['test_method'] = custom_method()

session = Session()
session.events.register('creating-client-class.s3', add_custom_method())

