@extends('layouts.admin')

@section('content')
    <div class="bg-white rounded-lg shadow-lg p-6 max-w-2xl mx-auto">
        <h1 class="text-2xl font-bold text-gray-800 mb-6">Tambah Dosen</h1>

        <form method="POST" action="{{ route('admin.dosen.update', $dosen->id) }}" class="space-y-4">
            @csrf
            @method('PUT')
            <div>
                <label class="block text-sm font-medium text-gray-700">NIP</label>
                <input type="text" name="nip" class="w-full border rounded px-3 py-2" required value="{{ old('nip', $dosen->nip) }}">
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700">Nama</label>
                <input type="text" name="name" class="w-full border rounded px-3 py-2" required value="{{ old('name', $dosen->name) }}">
            </div>
            <div>
                <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
                <div class="flex">
                    <input type="text" name="email_prefix" class="w-full border rounded px-3 py-2" required value="{{ old('email_prefix', explode('@', $dosen->email)[0]) }}">
                    <span class="bg-gray-300 p-3 border rounded-r-lg text-gray-700">@it.lecturer.pens.ac.id</span>
                </div>
                <input type="hidden" id="email" name="email">
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700">Password</label>
                <input type="password" name="password" class="w-full border rounded px-3 py-2" required>
            </div>
            <div class="flex justify-between items-center">
                <a href="{{ route('admin.dosen.index') }}" class="text-sm text-gray-600 hover:underline">← Kembali</a>
                <button type="submit" class="bg-blue-500 text-white px-5 py-2 rounded hover:bg-blue-600">
                    Simpan
                </button>
            </div>
        </form>
    </div>
@endsection
