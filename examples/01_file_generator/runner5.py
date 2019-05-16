from kitty.targets.application import ApplicationTarget
from kitty.fuzzers.guidedfuzzer import GuidedFuzzer
from kitty.interfaces import WebInterface
from kitty.model import String, Template, DetField, Static
from kitty.model import GuidedModel
import time
t1 = Template(name='T1', fields=[
    Static(value=b'\x00\x00\x00\x00'),
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
model = GuidedModel(indir = "indir", outdir = "outdir")
model.connect(t1)
# model.connect(t1, t2)
# model.connect(t2, t4)
# model.connect(t1, t3)
# model.connect(t3, t4)
seq = model.get_sequence()
at = ApplicationTarget(name="at", path="/home/ly/abc/2-4cov.out", args=[], tempfile='./tmp/fuzzed', sancov_path="/home/ly/abc/sancov", env={"ASAN_OPTIONS":"coverage=1:coverage_direct=1:coverage_dir='/home/ly/abc/sancov':log_path='/home/ly/abc/sancov_log'"})
fuzzer = GuidedFuzzer(name="Example 1 - File Generator")
fuzzer.set_interface(WebInterface(port=26004))
fuzzer.set_model(model)
fuzzer.set_target(at)
print time.strftime("%Y%m%d-%H%M%S")
fuzzer.start()
print time.strftime("%Y%m%d-%H%M%S")