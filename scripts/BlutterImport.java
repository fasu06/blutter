// Import Blutter function names, Dart structures and Thread/Object Pool annotations.
// @category Blutter

import java.io.BufferedReader;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;

public class BlutterImport extends GhidraScript {
    private final Map<String, StructureDataType> structures = new HashMap<>();
    private final Map<String, Long> counts = new HashMap<>();
    private final Map<Long, String> pendingAnnotations = new HashMap<>();
    private Address base;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open libapp.so before running this script");
        }
        String[] args = getScriptArgs();
        File data = args.length == 0 ? askFile("Select Blutter blutter.tsv", "Import") : new File(args[0]);
        base = args.length > 1 ? toAddr(args[1]) : currentProgram.getImageBase();
        if (base == null) {
            throw new IllegalArgumentException("Invalid load base");
        }
        if (!"AARCH64".equalsIgnoreCase(currentProgram.getLanguage().getProcessor().toString())) {
            throw new IllegalArgumentException("This importer supports Blutter ARM64 output");
        }
        structures.clear();
        counts.clear();
        pendingAnnotations.clear();
        validateInput(data);
        long started = System.nanoTime();
        try (BufferedReader reader = Files.newBufferedReader(data.toPath(), StandardCharsets.UTF_8)) {
            if (!"BLUTTER_GHIDRA\t1".equals(reader.readLine())) {
                throw new IllegalArgumentException("Unsupported Blutter data format");
            }
            String line;
            boolean saved = false;
            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                String[] row = line.split("\t", -1);
                if (!row[0].equals("M") && !saved) {
                    saveStructures();
                    saved = true;
                }
                try {
                    switch (row[0]) {
                        case "M": addMember(row); break;
                        case "F": addFunction(Long.parseLong(row[1]), Long.parseLong(row[2])); break;
                        case "N": setName(Long.parseLong(row[1]), decode(row[2])); break;
                        case "O": annotate(Long.parseLong(row[1]), Integer.parseInt(row[2]), row[3]); break;
                        default: throw new IllegalArgumentException("Unknown record: " + row[0]);
                    }
                    count(row[0]);
                }
                catch (CancelledException error) {
                    throw error;
                }
                catch (Exception error) {
                    if (row[0].equals("M")) {
                        throw error;
                    }
                    long failures = count(row[0] + "_failed");
                    if (failures <= 10) {
                        printerr(row[0] + " " + row[1] + ": " + error.getMessage());
                    }
                }
            }
            if (!saved) {
                saveStructures();
            }
        }
        for (Map.Entry<Long, String> entry : pendingAnnotations.entrySet()) {
            monitor.checkCancelled();
            Address address = base.add(entry.getKey());
            String old = currentProgram.getListing().getComment(CommentType.EOL, address);
            String annotation = entry.getValue();
            if (old == null || old.isEmpty()) {
                currentProgram.getListing().setComment(address, CommentType.EOL, annotation);
            }
            else if (!old.contains(annotation)) {
                currentProgram.getListing().setComment(address, CommentType.EOL, old + "\n" + annotation);
            }
        }
        println("Blutter import finished in " + ((System.nanoTime() - started) / 1_000_000_000.0) +
            "s: " + counts + "; annotated instructions: " + pendingAnnotations.size());
    }

    private void validateInput(File data) throws Exception {
        Map<String, Integer> sizes = new HashMap<>();
        AddressSetView executable = currentProgram.getMemory().getExecuteSet();
        boolean membersDone = false;
        try (BufferedReader reader = Files.newBufferedReader(data.toPath(), StandardCharsets.UTF_8)) {
            if (!"BLUTTER_GHIDRA\t1".equals(reader.readLine())) {
                throw new IllegalArgumentException("Unsupported Blutter data format");
            }
            String line;
            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                String[] row = line.split("\t", -1);
                int length = row[0].equals("M") ? 5 : row[0].equals("O") ? 4 : 3;
                if (row.length != length || !"MFNO".contains(row[0]) || row[0].length() != 1) {
                    throw new IllegalArgumentException("Malformed Blutter record");
                }
                if (row[0].equals("M")) {
                    if (membersDone || !(row[1].equals("DartThread") || row[1].equals("DartObjectPool")) ||
                            Integer.parseInt(row[2]) != sizes.getOrDefault(row[1], 0)) {
                        throw new IllegalArgumentException("Invalid structure member order");
                    }
                    decode(row[3]);
                    decode(row[4]);
                    sizes.put(row[1], Math.addExact(sizes.getOrDefault(row[1], 0), 8));
                }
                else {
                    membersDone = true;
                    Address address = base.add(Long.parseLong(row[1]));
                    if (Long.parseLong(row[1]) < 0 || !currentProgram.getMemory().contains(address)) {
                        throw new IllegalArgumentException("Blutter address outside loaded image: " + address);
                    }
                    if (row[0].equals("F")) {
                        long end = Long.parseLong(row[2]);
                        if (end <= Long.parseLong(row[1]) ||
                                !executable.contains(address, base.add(end - 1))) {
                            throw new IllegalArgumentException("Function outside executable memory: " + address);
                        }
                    }
                    else if (row[0].equals("N")) {
                        if (decode(row[2]).isEmpty()) {
                            throw new IllegalArgumentException("Empty symbol name");
                        }
                    }
                    else if (Integer.parseInt(row[2]) < 0 || !sizes.containsKey(row[3])) {
                        throw new IllegalArgumentException("Invalid offset record");
                    }
                }
            }
        }
        if (sizes.size() != 2) {
            throw new IllegalArgumentException("Expected two Dart structures");
        }
    }

    private long count(String kind) {
        long value = counts.getOrDefault(kind, 0L) + 1;
        counts.put(kind, value);
        if (value % 5000 == 0) {
            monitor.setMessage("Blutter " + kind + ": " + value);
            println(kind + ": " + value);
        }
        return value;
    }

    private static String decode(String value) {
        return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private void addMember(String[] row) {
        DataTypeManager manager = currentProgram.getDataTypeManager();
        StructureDataType structure = structures.computeIfAbsent(row[1], name ->
            new StructureDataType(new CategoryPath("/Blutter"), name, 0, manager));
        int offset = Integer.parseInt(row[2]);
        if (offset != structure.getNumComponents() * 8) {
            throw new IllegalArgumentException("Non-contiguous structure member: " + row[1]);
        }
        structure.add(Undefined8DataType.dataType, 8,
            SymbolUtilities.replaceInvalidChars(decode(row[3]), true), decode(row[4]));
    }

    private void saveStructures() {
        if (structures.size() != 2) {
            throw new IllegalArgumentException("Expected two Dart structures");
        }
        DataTypeManager manager = currentProgram.getDataTypeManager();
        for (StructureDataType structure : structures.values()) {
            String path = structure.getPathName();
            DataType existing = manager.getDataType(path);
            if (existing != null && !existing.isEquivalent(structure)) {
                throw new IllegalStateException("Conflicting data type " + path +
                    "; rename the existing type before importing");
            }
        }
        for (StructureDataType structure : structures.values()) {
            manager.resolve(structure, DataTypeConflictHandler.KEEP_HANDLER);
        }
    }

    private void addFunction(long start, long end) throws Exception {
        Address address = base.add(start);
        if (currentProgram.getFunctionManager().getFunctionAt(address) != null) {
            return;
        }
        if (end <= start || !currentProgram.getMemory().contains(address) ||
                !currentProgram.getMemory().contains(base.add(end - 1))) {
            throw new IllegalArgumentException("Function range is outside loaded memory");
        }
        AddressSet body = new AddressSet(address, base.add(end - 1));
        DisassembleCommand command = new DisassembleCommand(address, body, true);
        command.enableCodeAnalysis(false);
        command.applyTo(currentProgram, monitor);
        monitor.checkCancelled();
        if (getInstructionAt(address) == null) {
            throw new IllegalStateException("Cannot disassemble function entry");
        }
        Function created = currentProgram.getFunctionManager().createFunction(
            null, address, body, SourceType.IMPORTED);
        if (created == null) {
            throw new IllegalStateException("Function body overlaps an existing function");
        }
    }

    private void setName(long offset, String original) throws Exception {
        Address address = base.add(offset);
        if (!currentProgram.getMemory().contains(address)) {
            throw new IllegalArgumentException("Name address is outside loaded memory");
        }
        String name = SymbolUtilities.replaceInvalidChars(original.replace("::", "__"), true);
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function != null) {
            if (!function.getName().equals(name)) {
                function.setName(name, SourceType.IMPORTED);
            }
        }
        else {
            Symbol symbol = currentProgram.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
            symbol.setPrimary();
        }
    }

    private void annotate(long offset, int operand, String type) throws Exception {
        Instruction instruction = getInstructionAt(base.add(offset));
        if (instruction == null) {
            count("O_skipped");
            return;
        }
        String register = type.equals("DartThread") ? "x26" : "x27";
        // Capstone and Ghidra can split operands differently; inspect Ghidra's decoded memory operand.
        Long displacement = null;
        if (operand < instruction.getNumOperands()) {
            displacement = memberOffset(instruction, operand, register);
        }
        if (displacement == null) {
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                displacement = memberOffset(instruction, i, register);
                if (displacement != null) {
                    break;
                }
            }
        }
        StructureDataType structure = structures.get(type);
        if (displacement == null || structure == null || displacement < 0 ||
                displacement >= (long) structure.getNumComponents() * 8) {
            count("O_skipped");
            return;
        }
        int index = (int) (displacement / 8);
        String field = structure.getComponent(index).getFieldName();
        String annotation = "[Blutter] " + type + "." + field;
        if (displacement % 8 != 0) {
            annotation += "+0x" + Long.toHexString(displacement % 8);
        }
        String previous = pendingAnnotations.get(offset);
        pendingAnnotations.put(offset, previous == null || previous.equals(annotation) ? annotation :
            previous + "\n" + annotation);
    }

    private static Long memberOffset(Instruction instruction, int operand, String expectedRegister) {
        String representation = instruction.getDefaultOperandRepresentation(operand);
        if (!representation.contains("[") || representation.contains("!") ||
                representation.indexOf(']') != representation.length() - 1) {
            return null;
        }
        int registerCount = 0;
        boolean baseMatches = false;
        Long displacement = null;
        for (Object object : instruction.getOpObjects(operand)) {
            if (object instanceof Register) {
                if (++registerCount > 1) {
                    return null;
                }
                Register register = (Register) object;
                if (!register.getName().equalsIgnoreCase(expectedRegister)) {
                    return null; // Indexed addressing needs runtime register values.
                }
                baseMatches = true;
            }
            else if (object instanceof Scalar) {
                if (displacement != null) {
                    return null;
                }
                displacement = ((Scalar) object).getSignedValue();
            }
        }
        return baseMatches ? (displacement == null ? Long.valueOf(0) : displacement) : null;
    }
}
