#include "pep.h"
namespace pepenet_social {
  ibool pep_args::loadArgsFromJson()
  {
    if (!m_schema_valid)
    {
      return ibool{ false, std::string("Json schema has to be validated before args can be loaded") };
    }
    if (!m_json.HasMember("msg"))
    {
      return ibool{ false, std::string("json field msg is required!") };
    }
    else
    {
      m_msg = m_json["msg"].GetString();
    }
    if (m_json.HasMember("pseudonym"))
    {
      m_pseudonym = m_json["pseudonym"].GetString();
    }
    if (m_json.HasMember("sk_seed"))
    {
      if (!m_json.HasMember("post_pk"))
      {
        m_valid_args = false;
        return ibool{ false, std::string("json field post_pk is required when sk_seed is defined!") };
      }
      m_sk_seed = m_json["sk_seed"].GetString();
    }
    if (m_json.HasMember("post_pk"))
    {
      m_post_pk = m_json["post_pk"].GetBool();
      if (!m_json.HasMember("sk_seed"))
      {
        m_valid_args = false;
        return ibool{ false, std::string("json field sk_seed is required when post_pk is defined!") };
      }
    }
    if (m_json.HasMember("tx_ref"))
    {
      std::string tx_ref_hex = m_json["tx_ref"].GetString();
      crypto::hash tx_ref_parsed;
      if (!epee::string_tools::hex_to_pod(tx_ref_hex, tx_ref_parsed))
      {
        m_valid_args = false;
        return ibool{ false, std::string("unable to parse tx_ref from json!") };
      }
      m_tx_ref = tx_ref_parsed;
    }
    if (m_json.HasMember("pepetag"))
    {
      m_pepetag = m_json["pepetag"].GetString();
    }
    if (m_json.HasMember("donation_address"))
    {
      m_donation_address = m_json["donation_address"].GetString();
    }
    
    m_valid_args = true;
    return ibool{ true, INFO_NULLOPT };
  }

  ibool pep::loadFromSocialArgs(pep_args const& args)
  {
    if (!args.m_valid_args)
    {
      return ibool{ false, std::string("invalid social args") };
    }
    //copy base fields
    m_msg = args.m_msg;
    m_pseudonym = args.m_pseudonym;
    m_tx_ref = args.m_tx_ref;
    m_pepetag = args.m_pepetag;
    m_donation_address = args.m_donation_address;
    //create pep
    ibool r = dumpBaseToProto(); //base
    if (!r.b)
    {
      return r;
    }
    if (args.m_sk_seed.has_value()) //create sig
    {
      pepenet_social_protos::pep_base* base_ptr = m_proto.release_base(); //get base prt
      //get keys for signing
      crypto::public_key pk;
      crypto::secret_key sk;
      bool r = pepenet_social::secret_key_from_seed(args.m_sk_seed.value(), sk);
      if (!r)
      {
        return ibool{ r, std::string("failed to generate sk from sk_seed") };
      }
      r = crypto::secret_key_to_public_key(sk, pk);
      if (!r)
      {
        return ibool{ r, std::string("failed to generate pk from sk") };
      }
      //add pk to base if requested
      if (args.m_post_pk.value_or(false))
      {
        bytes pk_bytes(pk.data, 32);
        base_ptr->set_pk(pk_bytes);
      }
      //sign binary base
      bytes base_bytes;
      base_ptr->SerializeToString(&base_bytes);
      m_proto.set_allocated_base(base_ptr); //give base back to proto
      
      crypto::signature sig;
      pepenet_social::sign_msg(base_bytes, sig, pk, sk);
      //convert sig to bytes and set it to proto
      bytes sig_bytes = bytes(sig.c.data, 32) + bytes(sig.r.data, 32);
      //set the sig and pk
      m_proto.set_sig(sig_bytes);
      m_sig = sig;
      m_pk = pk;
    }
  }

  ibool pep::dumpBaseToProto()
  {
    pepenet_social_protos::pep_base base;
    base.set_msg(m_msg);
    if (m_pseudonym.has_value())
    {
      base.set_pseudonym(m_pseudonym.value());
    }
    if (m_tx_ref.has_value())
    {
      base.set_tx_ref(std::string(m_tx_ref.value().data, 32));
    }
    if (m_pepetag.has_value())
    {
      base.set_pepetag(m_pepetag.value());
    }
    if (m_donation_address.has_value())
    {
      base.set_donation_address(m_donation_address.value());
    }
    m_proto.set_allocated_base(&base);
  }

  ibool pep::dumpToProto()
  {
    dumpBaseToProto();
    bytes sig_bytes = bytes(m_sig.value().c.data, 32) + bytes(m_sig.value().r.data, 32);
    m_proto.set_sig(sig_bytes);
  }
  
  ibool pep::loadFromProto()
  {
    
  }

}