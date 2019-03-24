
from kitty.fuzzers import ServerFuzzer
from kitty.interfaces import WebInterface
from katnip.controllers.server.local_process import LocalProcessController
from katnip.targets.application import ApplicationTarget
from kitty.model import GraphModel
from kitty.model import String
from kitty.model import Template
from bitstring import BitArray, Bits


t1 = Template(name='T1', fields=[
    String('The default string', name='S1_1'),
    String('Another string', name='S1_2'),
])
t2 = Template(name='T2', fields=[
    String('Thfdsafdsa string', name='S1_1'),
    String('Anothedfsafdsafdstring', name='S1_2'),
])
t3 = Template(name='T3', fields=[
    String('Thfdsgfdgring', name='S1_1'),
    String('Anofdsgfdsging', name='S1_2'),
])
t4 = Template(name='T4', fields=[
    String('The dgfdsgfdsring', name='S1_1'),
    String('Anfgdsgfdsring', name='S1_2'),
])
model = GraphModel()
model.connect(t1)
model.connect(t1, t2)
model.connect(t2, t4)
model.connect(t1, t3)
model.connect(t3, t4)
model.get_sequence()
queue_cur = model._sequences[0]
node = queue_cur[-1].dst
node._det_finish = True
node_val = BitArray(node._default_value).copy()
node_val.invert(range(0, 1))
node.set_current_value(Bits(node_val))
a = node.render()
print a