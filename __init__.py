"""
easypatch
Plugin for patching target of a memory operation from right click menu.
Doesn't work on .bss section, and probably also doesn't work with debuggers.
"""
from binaryninja import interaction
from binaryninja import plugin
from binaryninja import function
from binaryninja.lowlevelil import LowLevelILOperation
from binaryninja.lowlevelil import LowLevelILInstruction
from binaryninja.enums import SegmentFlag

class MemoryReference:
    def __init__(self, addr, operation):
        self.addr = addr
        self.operation = operation
    def __str__(self):
        if isinstance(self.operation, LowLevelILOperation):
            operation = self.operation.name
        else:
            operation = 'OTHER'
        return '%s: %x' % (operation, self.addr)
    def __repr__(self):
        return str(self)


def get_memory_operands(il):
    """
    Recursively scans a LowLevelILInstruction for loads or stores
    and returns a list of MemoryReference for all constant memory operands
    referenced by the instruction
    """ 
    if not isinstance(il, LowLevelILInstruction):
        return []
    print il
    result = []
    if il.operation == LowLevelILOperation.LLIL_LOAD:
        if il.src.operation == LowLevelILOperation.LLIL_CONST:
            result += [MemoryReference(il.src.value, il.operation)]
    if il.operation == LowLevelILOperation.LLIL_STORE:
        if il.dest.operation == LowLevelILOperation.LLIL_CONST:
            result += [MemoryReference(il.dest.value, il.operation)]
        elif il.src.operation == LowLevelILOperation.LLIL_CONST:
            result += [MemoryReference(il.src.value, None)]
    if len(result) > 0:
        return result
 
    result = []
    for operand in il.operands:
        result += get_memory_operands(operand)
    return result

def get_memory_operands_at(bv, addr):
    """
    Returns a list of MemoryReference at the 
    given address of a BinaryView
    """
    return get_memory_operands(get_il_at(bv,addr))

def get_il_at(bv, addr):
    """
    Convert an address to low level il
    """
    function = bv.get_basic_blocks_at(addr)[0].function
    return function.low_level_il[function.get_low_level_il_at(addr)]

#Placeholder for when we can make this work right
def make_valid_for_writing(bv, base_addr, size):
    #Doesn't work right. Short circuit until it does
    return False
    valid = True

    buffer = '\0' * size
    # Save off old buffer in case anything was already there
    for i, addr in enumerate(xrange(base_addr, base_addr + size)):
        try:
            buffer[index] = bv.read(addr)
        except:
            pass
    flags = 0
    flags |= SegmentFlag.SegmentContainsData
    flags |= SegmentFlag.SegmentContainsCode
    flags |= SegmentFlag.SegmentWritable
    flags |= SegmentFlag.SegmentReadable
    bv.add_user_segment(base_addr, size, 0,size, flags)

    if not bv.write(base_addr, buffer):
        print 'Could not write old data back'
        return False
    return True
    
        
    
def easypatch(bv, addr):
    """
    Shows a dialog containing all memory operands at current instruction
    and prompts for data to overwrite with. Expression is eval()ed so
    \n and \0 are valid inputs
    """
    targets = get_memory_operands_at(bv, addr)
    targets_field = interaction.ChoiceField('Patch Target:', targets)
    patch_text_field = interaction.TextLineField('Patch text:')
    valid_input = interaction.get_form_input([targets_field,
                                        patch_text_field],
                                       'easypatch')
    
    if valid_input:
        target = targets[targets_field.result].addr
        patch_text = eval("'%s'" % patch_text_field.result)

        if not bv.write(target, patch_text):
            if not make_valid_for_writing(bv, target, len(patch_text)):
                interaction.show_message_box('easypatch', 'Failed to make writable to %x' % target)
            elif not bv.write(target, patch_text):
                interaction.show_message_box('easypatch', 'Failed to write to %x' % target)
            else:
                function = bv.get_basic_blocks_at(addr)[0].function
                function.reanalyze()                
        else:
            function = bv.get_basic_blocks_at(addr)[0].function
            function.reanalyze()
                                                    

plugin.PluginCommand.register_for_address('Easy Patch', 'Patch in user defined bytes', easypatch)
