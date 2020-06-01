from ecpy.curves import Curve,Point
ec = Curve.get_curve('secp256k1')

def __repr__(self):
	return self.__str__()

setattr(Point, '__repr__', __repr__)

def point(x,y):
	return Point(x,y,ec)

gen = ec.generator