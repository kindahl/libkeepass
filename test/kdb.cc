/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <fstream>

#include <gtest/gtest.h>

#include "kdb.hh"
#include "key.hh"

using namespace keepass;

namespace {

std::string GetTestPath(const std::string& name) {
  return "./test/data/kdb/" + name;
}

std::string GetTmpPath(const std::string& name) {
  return "./test/tmp/" + name;
}

std::string GetTestJson(const std::string& name) {
  std::ifstream file(GetTestPath(name));
  std::string file_str((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());

  // Compact the JSON by removing all white space not present in string
  // literals.
  char quote = '\0';
  std::string json;
  for (char c : file_str) {
    if (quote != '\0') {
      if (c == quote)
        quote = '\0';

      json.push_back(c);
    } else if (c == '"' || c == '\'') {
      quote = c;
      json.push_back(c);
    } else if (!std::isspace<char>(c, std::locale::classic())) {
      json.push_back(c);
    }
  }

  return json;
}

}   // namespace

TEST(KdbTest, CorrectPassword) {
  Key key("password");

  KdbFile file;
  EXPECT_NO_THROW(file.Import(GetTestPath("groups-1-empty-pw-aes.kdb"), key));
}

TEST(KdbTest, InvalidPassword) {
  Key key("wrong_password");

  KdbFile file;
  EXPECT_THROW(file.Import(GetTestPath("groups-1-empty-pw-aes.kdb"), key),
               std::runtime_error);
}

TEST(KdbTest, ImportGroups1) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-3-pw-aes.json"));
}

TEST(KdbTest, ImportGroups2) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-3-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-4-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-4-pw-aes.json"));
}

TEST(KdbTest, ImportGroups3) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-3-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-3-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-3-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-3-random_entry-1-pw-aes.json"));
}

TEST(KdbTest, ImportGroups4) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-3-pw-aes.json"));
}

TEST(KdbTest, ImportGroups5) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-3-pw-aes.json"));
}

TEST(KdbTest, ImportGroups6) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-3-pw-aes.json"));
}

TEST(KdbTest, ImportGroups7) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-3-pw-aes.json"));
}

TEST(KdbTest, ImportGroups8) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-8-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-8-empty-pw-aes.json"));
}

TEST(KdbTest, ImportGroups9) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-9-default-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-9-default-pw-aes.json"));
}

TEST(KdbTest, ImportComplex1) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-pw-aes.kdb"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-pw-aes.json"));
}

TEST(KdbTest, ImportComplex1KeyFile) {
  Key key;
  key.SetKeyFile(GetTestPath("complex-1-key-tf.key"));

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-key-tf.kdb"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-key-tf.json"));
}

TEST(KdbTest, ImportComplex1KeyFileAndPassword) {
  Key key("password");
  key.SetKeyFile(GetTestPath("complex-1-key_pw-tf.key"));

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-key_pw-tf.kdb"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-key_pw-tf.json"));
}

TEST(KdbTest, ExportGroups1) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 4> test_files = {{
    { GetTestPath("groups-1-empty-pw-aes.kdb"),
      GetTmpPath("groups-1-empty-pw-aes.kdb"),
      GetTestJson("groups-1-empty-pw-aes.json") },
    { GetTestPath("groups-1-random_entry-1-pw-aes.kdb"),
      GetTmpPath("groups-1-random_entry-1-pw-aes.kdb"),
      GetTestJson("groups-1-random_entry-1-pw-aes.json") },
    { GetTestPath("groups-1-random_entry-2-pw-aes.kdb"),
      GetTmpPath("groups-1-random_entry-2-pw-aes.kdb"),
      GetTestJson("groups-1-random_entry-2-pw-aes.json") },
    { GetTestPath("groups-1-random_entry-3-pw-aes.kdb"),
      GetTmpPath("groups-1-random_entry-3-pw-aes.kdb"),
      GetTestJson("groups-1-random_entry-3-pw-aes.json") }
  }};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({
      db = file.Import(t.src_path, key);
    });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({
      db = file.Import(t.dst_path, key);
    });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root().lock();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbTest, ExportGroups2) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 5> test_files = {{
    { GetTestPath("groups-2-empty-pw-aes.kdb"),
      GetTmpPath("groups-2-empty-pw-aes.kdb"),
      GetTestJson("groups-2-empty-pw-aes.json") },
    { GetTestPath("groups-2-random_entry-1-pw-aes.kdb"),
      GetTmpPath("groups-2-random_entry-1-pw-aes.kdb"),
      GetTestJson("groups-2-random_entry-1-pw-aes.json") },
    { GetTestPath("groups-2-random_entry-2-pw-aes.kdb"),
      GetTmpPath("groups-2-random_entry-2-pw-aes.kdb"),
      GetTestJson("groups-2-random_entry-2-pw-aes.json") },
    { GetTestPath("groups-2-random_entry-3-pw-aes.kdb"),
      GetTmpPath("groups-2-random_entry-3-pw-aes.kdb"),
      GetTestJson("groups-2-random_entry-3-pw-aes.json") },
    { GetTestPath("groups-2-random_entry-4-pw-aes.kdb"),
      GetTmpPath("groups-2-random_entry-4-pw-aes.kdb"),
      GetTestJson("groups-2-random_entry-4-pw-aes.json") }
  }};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({
      db = file.Import(t.src_path, key);
    });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({
      db = file.Import(t.dst_path, key);
    });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root().lock();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbTest, ExportGroups3) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 2> test_files = {{
    { GetTestPath("groups-3-empty-pw-aes.kdb"),
      GetTmpPath("groups-3-empty-pw-aes.kdb"),
      GetTestJson("groups-3-empty-pw-aes.json") },
    { GetTestPath("groups-3-random_entry-1-pw-aes.kdb"),
      GetTmpPath("groups-3-random_entry-1-pw-aes.kdb"),
      GetTestJson("groups-3-random_entry-1-pw-aes.json") }
  }};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({
      db = file.Import(t.src_path, key);
    });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({
      db = file.Import(t.dst_path, key);
    });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root().lock();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbTest, ExportGroups4) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 4> test_files = {{
    { GetTestPath("groups-4-empty-pw-aes.kdb"),
      GetTmpPath("groups-4-empty-pw-aes.kdb"),
      GetTestJson("groups-4-empty-pw-aes.json") },
    { GetTestPath("groups-4-random_entry-1-pw-aes.kdb"),
      GetTmpPath("groups-4-random_entry-1-pw-aes.kdb"),
      GetTestJson("groups-4-random_entry-1-pw-aes.json") },
    { GetTestPath("groups-4-random_entry-2-pw-aes.kdb"),
      GetTmpPath("groups-4-random_entry-2-pw-aes.kdb"),
      GetTestJson("groups-4-random_entry-2-pw-aes.json") },
    { GetTestPath("groups-4-random_entry-3-pw-aes.kdb"),
      GetTmpPath("groups-4-random_entry-3-pw-aes.kdb"),
      GetTestJson("groups-4-random_entry-3-pw-aes.json") }
  }};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({
      db = file.Import(t.src_path, key);
    });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({
      db = file.Import(t.dst_path, key);
    });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root().lock();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbTest, ExportGroups5) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 4> test_files = {{
    { GetTestPath("groups-5-empty-pw-aes.kdb"),
      GetTmpPath("groups-5-empty-pw-aes.kdb"),
      GetTestJson("groups-5-empty-pw-aes.json") },
    { GetTestPath("groups-5-random_entry-1-pw-aes.kdb"),
      GetTmpPath("groups-5-random_entry-1-pw-aes.kdb"),
      GetTestJson("groups-5-random_entry-1-pw-aes.json") },
    { GetTestPath("groups-5-random_entry-2-pw-aes.kdb"),
      GetTmpPath("groups-5-random_entry-2-pw-aes.kdb"),
      GetTestJson("groups-5-random_entry-2-pw-aes.json") },
    { GetTestPath("groups-5-random_entry-3-pw-aes.kdb"),
      GetTmpPath("groups-5-random_entry-3-pw-aes.kdb"),
      GetTestJson("groups-5-random_entry-3-pw-aes.json") }
  }};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({
      db = file.Import(t.src_path, key);
    });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({
      db = file.Import(t.dst_path, key);
    });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root().lock();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbTest, ExportGroups6) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 4> test_files = {{
    { GetTestPath("groups-6-empty-pw-aes.kdb"),
      GetTmpPath("groups-6-empty-pw-aes.kdb"),
      GetTestJson("groups-6-empty-pw-aes.json") },
    { GetTestPath("groups-6-random_entry-1-pw-aes.kdb"),
      GetTmpPath("groups-6-random_entry-1-pw-aes.kdb"),
      GetTestJson("groups-6-random_entry-1-pw-aes.json") },
    { GetTestPath("groups-6-random_entry-2-pw-aes.kdb"),
      GetTmpPath("groups-6-random_entry-2-pw-aes.kdb"),
      GetTestJson("groups-6-random_entry-2-pw-aes.json") },
    { GetTestPath("groups-6-random_entry-3-pw-aes.kdb"),
      GetTmpPath("groups-6-random_entry-3-pw-aes.kdb"),
      GetTestJson("groups-6-random_entry-3-pw-aes.json") }
  }};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({
      db = file.Import(t.src_path, key);
    });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({
      db = file.Import(t.dst_path, key);
    });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root().lock();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbTest, ExportGroups7) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 4> test_files = {{
    { GetTestPath("groups-7-empty-pw-aes.kdb"),
      GetTmpPath("groups-7-empty-pw-aes.kdb"),
      GetTestJson("groups-7-empty-pw-aes.json") },
    { GetTestPath("groups-7-random_entry-1-pw-aes.kdb"),
      GetTmpPath("groups-7-random_entry-1-pw-aes.kdb"),
      GetTestJson("groups-7-random_entry-1-pw-aes.json") },
    { GetTestPath("groups-7-random_entry-2-pw-aes.kdb"),
      GetTmpPath("groups-7-random_entry-2-pw-aes.kdb"),
      GetTestJson("groups-7-random_entry-2-pw-aes.json") },
    { GetTestPath("groups-7-random_entry-3-pw-aes.kdb"),
      GetTmpPath("groups-7-random_entry-3-pw-aes.kdb"),
      GetTestJson("groups-7-random_entry-3-pw-aes.json") }
  }};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({
      db = file.Import(t.src_path, key);
    });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({
      db = file.Import(t.dst_path, key);
    });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root().lock();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbTest, ExportGroups8) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 1> test_files = {{
    { GetTestPath("groups-8-empty-pw-aes.kdb"),
      GetTmpPath("groups-8-empty-pw-aes.kdb"),
      GetTestJson("groups-8-empty-pw-aes.json") }
  }};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({
      db = file.Import(t.src_path, key);
    });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({
      db = file.Import(t.dst_path, key);
    });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root().lock();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbTest, ExportGroups9) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;

  struct TestFiles {
    std::string src_path;
    std::string dst_path;
    std::string json;
  };
  std::array<TestFiles, 1> test_files = {{
    { GetTestPath("groups-9-default-pw-aes.kdb"),
      GetTmpPath("groups-9-default-pw-aes.kdb"),
      GetTestJson("groups-9-default-pw-aes.json") }
  }};

  for (auto& t : test_files) {
    EXPECT_NO_THROW({
      db = file.Import(t.src_path, key);
    });
    file.Export(t.dst_path, *db, key);
    EXPECT_NO_THROW({
      db = file.Import(t.dst_path, key);
    });
    std::remove(t.dst_path.c_str());

    std::shared_ptr<Group> root = db->root().lock();
    EXPECT_NE(root, nullptr);
    EXPECT_EQ(root->ToJson(), t.json);
  }
}

TEST(KdbTest, ExportComplex1) {
  Key key("password");

  std::string src_path = GetTestPath("complex-1-pw-aes.kdb");
  std::string dst_path = GetTmpPath("complex-1-pw-aes.kdb");
  std::string json = GetTestJson("complex-1-pw-aes.json");

  KdbFile file;
  std::unique_ptr<Database> db;

  EXPECT_NO_THROW({
    db = file.Import(src_path, key);
  });
  file.Export(dst_path, *db, key);
  EXPECT_NO_THROW({
    db = file.Import(dst_path, key);
  });
  std::remove(dst_path.c_str());

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), json);
}

TEST(KdbTest, ExportComplex1KeyFile) {
  Key key;
  key.SetKeyFile(GetTestPath("complex-1-key-tf.key"));

  std::string src_path = GetTestPath("complex-1-key-tf.kdb");
  std::string dst_path = GetTmpPath("complex-1-key-tf.kdb");
  std::string json = GetTestJson("complex-1-key-tf.json");

  KdbFile file;
  std::unique_ptr<Database> db;

  EXPECT_NO_THROW({
    db = file.Import(src_path, key);
  });
  file.Export(dst_path, *db, key);
  EXPECT_NO_THROW({
    db = file.Import(dst_path, key);
  });
  std::remove(dst_path.c_str());

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), json);
}

TEST(KdbTest, ExportComplex1KeyFileAndPassword) {
  Key key("password");
  key.SetKeyFile(GetTestPath("complex-1-key_pw-tf.key"));

  std::string src_path = GetTestPath("complex-1-key_pw-tf.kdb");
  std::string dst_path = GetTmpPath("complex-1-key_pw-tf.kdb");
  std::string json = GetTestJson("complex-1-key_pw-tf.json");

  KdbFile file;
  std::unique_ptr<Database> db;

  EXPECT_NO_THROW({
    db = file.Import(src_path, key);
  });
  file.Export(dst_path, *db, key);
  EXPECT_NO_THROW({
    db = file.Import(dst_path, key);
  });
  std::remove(dst_path.c_str());

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), json);
}
