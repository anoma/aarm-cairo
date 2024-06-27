# NIF for Elixir.Anoma.CairoVM

## To build the NIF module:

- Your NIF will now build along with your project.

## To load the NIF:

```elixir
defmodule Cairo.CairoVM do
  use Rustler, otp_app: :cairo, crate: "cairo_vm"

  # When your NIF is loaded, it will override this function.
  def cairo_vm_runner(_arg1, _arg2), do: :erlang.nif_error(:nif_not_loaded)
end
```

## TO compile CairoVM code

### Compile juvix code

Use the latest [Juvix compiler](https://github.com/anoma/juvix) to compile juvix program, and get compiled json file

```bash
juvix compile cairo cairo.juvix
```

### Run cairo_vm and generate the proof
An example can be found in "cairo_api_test"

```elixir
# Run cairo-vm
test "cairo_api_test" do
  // The file cairo.json is the output of Juvix compiler
  {:ok, program} = File.read("./native/cairo_vm/cairo.json")

  // The file cairo_input.json is what we use to input data into the program. If there's no input, it'll just be an empty string.
  {:ok, input} = File.read("./native/cairo_vm/cairo_input.json")

  // Run cairo vm
  {output, trace, memory, public_inputs} =
    Cairo.cairo_vm_runner(
      program,
      input
    )

  assert "17\n" = output

  # Prove and verify
  {proof, public_input} = Cairo.prove(trace, memory, public_inputs)
  assert true = Cairo.verify(proof, public_input)
end
```
